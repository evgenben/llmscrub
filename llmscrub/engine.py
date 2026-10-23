"""Reversible pseudonymisation of Linux configs and logs before sending them to an AI.

Design:
  * every detector produces candidate spans on the ORIGINAL text;
  * overlaps are resolved by priority (secrets > encoded fields > DNS/IP > names);
  * the output is built in one pass, so pseudonyms are never re-scanned;
  * the session keeps the mapping in memory; secrets are replaced
    irreversibly (their plaintext stays only in process memory, for the leak check).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Callable

from .config import Config
from .i18n import t as _t
from .ipmap import (
    IPMapper,
    IPV4_RE,
    IPV4_RE_TEXT,
    MASK_AFTER_RE,
    int2ip,
    ip2int,
    is_netmask,
    mask_len,
)

# --------------------------------------------------------------------------
# Built-in lists
# --------------------------------------------------------------------------

HOST_STOP = set(
    """
localhost localdomain localhost.localdomain ip6-localhost ip6-loopback ip6-allnodes
ip6-allrouters ip6-localnet ip6-mcastprefix broadcasthost ubuntu debian centos rhel
rocky alma fedora linux server host node master worker client mail smtp imap imaps pop
pop3 www web ftp ns ns1 ns2 ns3 ns4 dns ntp ldap ldaps kerberos kdc kpasswd proxy
gateway gw router firewall fw vpn db sql mysql postgres redis api app backend frontend
test dev stage staging prod production qa uat admin monitor monitoring log logs syslog
backup kernel systemd sudo cron sshd autodiscover autoconfig ipa ipa-ca cloud internal
private public default none any all unknown example invalid local lan home corp intranet
reboot yearly annually monthly weekly daily midnight hourly
""".split()
)

USER_KEEP = set(
    """
root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc
gnats nobody nogroup _apt syslog messagebus sshd polkitd ntp chrony _chrony postfix
postdrop dovecot dovenull nginx apache apache2 httpd mysql postgres redis bind named
unbound openvpn zabbix prometheus node_exporter grafana wazuh wazuh-indexer ossec sssd
dnsmasq tss uuidd tcpdump landscape pollinate fwupd-refresh usbmux avahi colord rtkit
adm sudo wheel staff users admin tty disk kmem dialout cdrom floppy plugdev lxd docker
ssl-cert shadow utmp video audio input render netdev kvm libvirt libvirt-qemu ipaapi
pkiuser dirsrv kdcproxy ods memcached git www gdm lightdm whoopsie kernoops saned pulse
geoclue hplip speech-dispatcher sddm rpc rpcuser statd _rpc _laurel invalid unknown
all any none user username name noreply no-reply postmaster mailer-daemon abuse
hostmaster webmaster nm-openvpn cups-pk-helper elasticsearch kibana logstash haproxy
keepalived snmp debian-snmp _flatpak dhcpcd systemd
""".split()
)

CN_KEEP = set(
    x.strip()
    for x in """
admin,admins,users,groups,accounts,computers,config,configuration,schema,services,
sysaccounts,etc,kerberos,masters,ipa,directory manager,manager,replication,sudo,
sudorules,sudocmds,sudocmdgroups,hbac,hbacservices,roles,privileges,permissions,
certificates,ca,cas,subordinateids,topology,dns,automount,otp,radiusproxy,views,
selinux,pbac,default,domain admins,domain users,enterprise admins,administrators,
builtin,system,public key services,trusts,ad,certprofiles,caacls,idoverride,
default trust view,ipaservers,ipausers,editors,trust admins
""".split(",")
    if x.strip()
)

KW_BASE = [
    r"pass(?:word|wd|phrase)?",
    r"pwd",
    r"secret",
    r"token",
    r"authtok",
    r"bindpw",
    r"rootpw",
    r"requirepass",
    r"masterauth",
    r"psk",
    r"credentials?",
    r"api[-_]?key",
    r"access[-_]?key",
    r"secret[-_]?key",
    r"private[-_]?key",
    r"client[-_]?secret",
    r"auth[-_]?key",
    r"session[-_]?key",
    r"enc(?:ryption)?[-_]?key",
    r"hmac[-_]?key",
    r"signing[-_]?key",
    r"master[-_]?key",
    r"license[-_]?key",
    r"key[-_]?base",
]

SECRET_VALUE_SKIP = set(
    """
yes no true false on off none null nil enabled disabled enable disable required
requisite sufficient optional include substack chauthtok auth account session
password passwd secret token prompt ask - * ** *** **** ******** redacted hidden
""".split()
)

# Category codes carried in Span.note (language independent).
KIND_LABEL = {k: k.lower() for k in (
    "ip", "inaddr", "dn", "fqdn", "host", "user", "name", "string", "hex",
    "SECRET", "HASH", "PAN", "KEY", "CERT",
)}

SECRET_KINDS = ("SECRET", "HASH", "PAN", "KEY", "CERT")

# --------------------------------------------------------------------------
# Static regexes
# --------------------------------------------------------------------------

LABEL = r"_?[A-Za-z0-9](?:[A-Za-z0-9_\-]*[A-Za-z0-9])?"

PEM_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Za-z0-9 ]+?)-----[ \t]*\r?\n(?P<v>[\s\S]*?)\r?\n?[ \t]*-----END (?P=label)-----"
)
ENV_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
OVPN_RE = re.compile(
    r"<(?P<tag>tls-auth|tls-crypt|tls-crypt-v2|secret|key|pkcs12|auth-user-pass|"
    r"http-proxy-user-pass|cert|ca|extra-certs|peer-fingerprint)>(?P<v>[\s\S]*?)</(?P=tag)>"
)
URI_CRED_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://(?P<u>[^:/\s@\[\]]+):(?P<v>[^@/\s]+)@")
AUTH_HDR_RE = re.compile(
    r"(?i)\b(?:proxy-)?authorization[\"']?[ \t]*[:=]?[ \t]*[\"']?"
    r"(?:basic|bearer|digest|token|negotiate|ntlm)[ \t]+(?P<v>[A-Za-z0-9+/=._~\-]{6,})"
)
JWT_RE = re.compile(r"\beyJ[\w\-]{6,}\.[\w\-]{6,}\.[\w\-]{6,}")
TOKEN_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{40,}|xox[abprs]-[\w\-]{10,}"
    r"|glpat-[\w\-]{20,}|AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9_\-]{20,})"
)
HASH_RE = re.compile(
    r"(?<![\w$])\$(?:1|2[abxy]?|5|6|7|y|gy|apr1|md5|sha1|argon2(?:id|i|d))\$[A-Za-z0-9./+=$,\-]{8,}"
    r"|(?i:\{(?:SSHA|SHA|SSHA256|SSHA384|SSHA512|SHA256|SHA384|SHA512|MD5|SMD5|CRYPT|PBKDF2[\w\-]*|ARGON2)\})"
    r"[A-Za-z0-9+/=$.,\-]{8,}"
)
PAN_RE = re.compile(r"(?<![\d\-])(?:\d[ \-]?){12,18}\d(?![\d\-])")
NETRC_RE = re.compile(r"(?i)\blogin[ \t]+(?P<u>\S+)[ \t]+password[ \t]+(?P<v>\S+)")
SASL_RE = re.compile(
    r"(?m)^[ \t]*\[[^\]\n]+\](?::\d+)?[ \t]+(?P<u>[^:\s@]+)(?:@[^:\s]+)?:(?P<v>\S+)[ \t]*$"
)
CLI_U_RE = re.compile(r"(?<!\S)(?:-u|--user)[ =](?P<u>[^:\s'\"]+):(?P<v>[^\s'\"]+)")
CLI_PW_RE = re.compile(
    r"(?i)(?<!\S)--pass(?:word)?[ =](?P<v>[^\s'\"]+)"
    r"|\bsshpass[ \t]+-p[ \t]*(?P<v2>\S+)"
    r"|\bmysql(?:dump|admin)?\b[^\n]*?[ \t]-p(?P<v3>[^\s\-'\"][^\s'\"]*)"
)
PSK_RE = re.compile(r"(?i)(?<![\w])PSK[ \t]+[\"'](?P<v>[^\"'\n]+)[\"']")
SNMP_RE = re.compile(
    r"(?im)^[ \t]*(?:#[ \t]*)?(?:ro|rw)community6?[ \t]+(?P<v>\S+)"
    r"|^[ \t]*(?:#[ \t]*)?com2sec6?[ \t]+\S+[ \t]+\S+[ \t]+(?P<v2>\S+)"
)
HEX_AUDIT_RE = re.compile(
    r"(?<![\w\-])(?P<k>proctitle|cmd|acct|exe|cwd|name|comm|data|path|old-name|new-name)"
    r"=(?P<v>[0-9A-F]{8,})(?![\w])"
)
INADDR_RE = re.compile(r"(?i)(?<![\w.\-])(?P<v>(?:\d{1,3}\.){1,4})in-addr\.arpa(?![\w\-])")
DN_DC_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<v>dc=[^,+\s\"=()]+(?:[ \t]*,[ \t]*dc=[^,+\s\"=()]+)+)"
)
DN_VAL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<a>uid|cn)=(?P<v>[^,=+\n\"()]+?)(?=[ \t]*,[ \t]*[A-Za-z]+=)"
)
LDAP_FILTER_RE = re.compile(
    r"(?i)\((?P<a>uid|cn|samaccountname|userprincipalname|memberuid)=(?P<v>[^)*\n@]+)(?:@[^)\n]*)?\)"
)
EMAIL_LOCAL_RE = re.compile(
    r"(?<![\w.+/\-])(?P<v>[A-Za-z0-9][\w.+\-]*)@(?=[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)"
    r"(?![\w.\-]*\.(?:service|socket|timer|target|mount|automount|slice|scope|path|device|swap)\b)"
)
# Person names: LDIF attributes and the GECOS field of /etc/passwd
PERSON_RE = re.compile(
    r"(?im)^(?:cn|sn|givenName|displayName|gecos|fullName|initials|gn):[ \t]*(?P<v>[^\n]*?)[ \t]*$"
    r"|^[a-z_][\w.\-]*:[^:\n]*:\d+:\d+:(?P<g>[^:,\n]+)"
)
NGINX_PASS_KEYS = {"proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass"}

# Learning (discovery of host / user names)
SYSLOG_HOST_RE = re.compile(
    r"(?m)^(?:<\d+>)?(?:[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)"
    r"[ \t]+(?P<h>[A-Za-z0-9][\w.\-]*)[ \t]+\S"
)
PROMPT_RE = re.compile(
    r"(?<![\w.\-])(?P<u>[a-z_][\w.\-]*)@(?P<h>[A-Za-z0-9][\w\-]*)(?=:[ \t]?[~/])"
    r"|\[(?P<u2>[a-z_][\w.\-]*)@(?P<h2>[A-Za-z0-9][\w\-]*)[ \t][^\]\n]*\][#$]"
)
ETC_HOSTS_RE = re.compile(
    r"(?m)^[ \t]*(?:\d{1,3}\.){3}\d{1,3}[ \t]+"
    r"(?P<names>[A-Za-z0-9][\w.\-]*(?:[ \t]+[A-Za-z0-9][\w.\-]*)*)[ \t]*(?:#.*)?$"
)
HOST_KV_RE = re.compile(
    r"(?im)(?:\b_?hostname[\"']?[ \t]*[:=][ \t]*[\"']?|^[ \t]*Static hostname:[ \t]*"
    r"|^[ \t]*Hostname[ \t]+|\brhost=)(?P<h>[A-Za-z0-9][A-Za-z0-9\-]*)(?![\w.\-])"
)
SSH_HOST_RE = re.compile(r"(?im)^[ \t]*Host[ \t]+(?P<names>[^#\n]+)$")
RSYSLOG_RE = re.compile(r"(?m)(?<![\w@])@@?(?P<h>[A-Za-z][A-Za-z0-9\-]*)(?=:\d|[ \t]*$)")
URI_HOST_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.\-]*://(?:[^@/\s]+@)?(?P<h>[A-Za-z][A-Za-z0-9\-]*)(?=[:/\s\"'>,;)]|$)"
)
NFS_RE = re.compile(
    r"(?m)^[ \t]*(?P<h>[A-Za-z][A-Za-z0-9\-]*):/"
    r"|(?<![\w.\-@/:])(?P<h2>[A-Za-z][A-Za-z\-]*\d[A-Za-z0-9\-]*):/(?!/)"
)
# X.509 subject fields that name the organisation or its location
X509_SUBJ_LINE_RE = re.compile(r"(?im)^.*\bsubject\b.*$")
X509_FIELD_RE = re.compile(r"(?:^|[,/=:][ \t]*)(?P<k>O|OU|L|ST)[ \t]*=[ \t]*(?P<v>[^,/\n]+?)[ \t]*(?=,|/|$)")

USER_LEARN_RES = [
    re.compile(p)
    for p in (
        r"\bAccepted [\w\-]+ for (?P<u>\S+) from",
        r"\bFailed [\w\-]+ for (?!invalid user )(?P<u>\S+) from",
        r"\b(?:authenticating|Disconnected from) user (?P<u>[\w.@\-]+)",
        r"\bsession (?:opened|closed) for user (?P<u>[\w.@\-]+)",
        r"\bby (?P<u>[\w.\-]+)\(uid=\d+\)",
        r"\bsudo(?:\[\d+\])?:[ \t]+(?P<u>[\w.@\-]+) :",
        r"\bsu(?:\[\d+\])?: \(to (?P<u>[\w.\-]+)\) (?P<u2>[\w.\-]+) on",
        r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+_)?(?:user|ruser|logname|acct|auid|uid|login|username|user_name)"
        r"=[\"']?(?P<u>[\w.@\-]+)",
        r"\b(?:uid|gid|euid|egid|suid|fsuid|sgid|fsgid|ouid|ogid)=\d+\((?P<u>[\w.\-]+)\)",
        r"/home/(?P<u>[\w.\-]+)",
        r"(?m)^(?P<u>[a-z_][\w.\-]*):[^:\n]*:\d+:\d+:",
        r"(?m)^(?P<u>[a-z_][\w.\-]*):(?:\$|!|\*)[^:\n]*:\d*:",
        r"(?m)^(?P<u>[a-z_][\w.\-]*):[^:\n]*:\d+:(?P<list>[\w.,\-]+)[ \t]*$",
        r"(?im)^[ \t]*(?:AllowUsers|DenyUsers)[ \t]+(?P<list>.+)$",
        r"(?im)^[ \t]*Match[ \t]+User[ \t]+(?P<list>\S+)",
        r"(?im)^[ \t]*(?:simple_allow_users|simple_deny_users)[ \t]*=[ \t]*(?P<list>.+)$",
        r"(?im)^[ \t]*User[ \t]+(?P<u>[\w.\-]+)[ \t]*$",
        r"(?m)^[\-dlcbps][rwxsStT\-]{9}[.+@]?[ \t]+\d+[ \t]+(?P<u>[\w.\-]+)[ \t]+(?P<u2>[\w.\-]+)[ \t]",
        r"\bfor user [\[\"']?(?P<u>[\w.@\-]+)",
        r"\bpassword changed for (?P<u>[\w.\-]+)",
        r"\bnew user: name=(?P<u>[\w.\-]+)",
        r"(?m)^(?P<u>[\w.\-]+)[ \t]+ALL[ \t]*=",
        r"(?<=[=,])\d+\((?P<u>[\w.\-]+)\)",
        r"\bUser (?P<u>[\w.\-]+) may run the following commands",
        r"(?m)^(?P<u>[a-z_][\w.\-]*)[ \t]+(?:pts/\d+|tty\w*|:\d+)[ \t]",
        r"(?m)^\S+[ \t]+\S+[ \t]+(?P<u>[A-Za-z_][\w.@\-]*)[ \t]+\[\d{1,2}/\w{3}/\d{4}:",
        r"\b(?:sudo|crontab|su|psql|mysql|ps|pkill|pgrep|killall|chage|passwd|usermod|userdel|loginctl"
        r"|runuser|lastlog|quota|at)\b[^\n|;&]*?[ \t]-[uU][ \t]*(?P<u>[a-z_][\w.\-]*)",
        r"(?m)(?:^|[$#>][ \t]+|[;&|][ \t]*)(?:sudo[ \t]+)?(?:id|groups|finger|chage[ \t]+-l|passwd[ \t]+-S"
        r"|getent[ \t]+(?:passwd|shadow|group)|userdel|su[ \t]+-l?|su)[ \t]+(?P<u>[a-z_][\w.\-]*)",
    )
]

TOKEN_SPLIT_RE = re.compile(r"[A-Za-z0-9]+")
PSEUDO_TOKEN_RE = re.compile(r"^(host|zone|org|user|name)\d{2,}$", re.IGNORECASE)
VALID_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]*$")
VALID_USER_RE = re.compile(r"^[A-Za-z_][\w.\-]*$")
HEXBLOB_RE = re.compile(r"^[0-9A-F]{6,}$")

UNMASK_RE = re.compile(
    r"(?P<ph><(?:SECRET|HASH|PAN|KEY|CERT)_\d{2,}>)"
    r"|(?P<inaddr>(?<![\w.\-])(?:\d{1,3}\.){1,4}in-addr\.arpa(?![\w\-]))"
    rf"|(?P<ip>{IPV4_RE_TEXT})"
    r"|(?P<dn>(?<![A-Za-z0-9])dc=[^,+\s\"=()]+(?:[ \t]*,[ \t]*dc=[^,+\s\"=()]+)+)"
    rf"|(?P<fqdn>(?<![A-Za-z0-9\-_])(?P<flabels>(?:{LABEL}\.)*)(?P<forg>org\d{{2,}})\.example(?![A-Za-z0-9\-]))"
    r"|(?P<tok>(?<![A-Za-z0-9])(?:host|zone|org|user|name)\d{2,}(?![A-Za-z0-9]))",
    re.IGNORECASE,
)

# Priorities: lower wins on overlap
P_BLOCK, P_SECRET, P_HEX, P_INADDR, P_DN, P_FQDN, P_IP, P_LOCAL, P_HOST, P_USER, P_STR = range(11)


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------


@dataclass
class Span:
    start: int
    end: int
    kind: str          # masked | secret | restored | derived | unknown | ambiguous | leak
    note: str = ""


@dataclass
class Finding:
    pane: str          # "in" (source text) or "out" (result text)
    start: int
    end: int
    level: str         # error | warn | info
    code: str          # stable identifier, see i18n "f.<code>"
    args: dict = field(default_factory=dict)

    @property
    def message(self) -> str:
        return _t("f." + self.code, **self.args)


@dataclass
class Result:
    text: str
    in_spans: list[Span] = field(default_factory=list)
    out_spans: list[Span] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Cand:
    start: int
    end: int
    prio: int
    kind: str
    make: Callable[[], str]
    note: str = ""


def _case(orig: str, pseudo: str) -> str:
    letters = [c for c in orig if c.isalpha()]
    if letters and all(c.isupper() for c in letters) and len(letters) > 1:
        return pseudo.upper()
    if letters and orig[:1].isupper() and all(c.islower() for c in letters[1:]):
        return pseudo.capitalize()
    return pseudo


def _uncase(tok: str, orig: str) -> str:
    """Inverse of _case: re-apply the case pattern of a pseudonym to the original."""
    letters = [c for c in tok if c.isalpha()]
    if letters and all(c.isupper() for c in letters) and len(letters) > 1:
        return orig.upper()
    transformed = _case(orig, "ab") != "ab"
    if tok[:1].isupper():
        return orig[:1].upper() + orig[1:].lower()
    return orig.lower() if transformed else orig


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


SEG_RE = re.compile(r"[A-Za-z0-9]+")
LEAK_IP_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w])(?!\.\d)(?!\.in-addr)", re.IGNORECASE)


_ASCII_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def find_names(text: str, names: set[str]) -> list[tuple[int, int]]:
    """Leftmost-longest occurrences of known names, bounded by non-alphanumerics.

    Equivalent to the regex (?<![A-Za-z0-9])(?:n1|n2|...)(?![A-Za-z0-9]) with
    case-insensitive matching, but linear in the text size: names are indexed
    by their first alphanumeric run instead of being tried one by one."""
    out: list[tuple[int, int]] = []
    if not names:
        return out
    index: dict[str, list[str]] = {}
    for n in names:
        m = SEG_RE.match(n)
        if m:
            index.setdefault(m.group(0), []).append(n)
    for v in index.values():
        v.sort(key=len, reverse=True)
    limit = 0
    tlen = len(text)
    for m in SEG_RE.finditer(text):
        s = m.start()
        if s < limit:
            continue
        cands = index.get(m.group(0).lower())
        if not cands:
            continue
        for n in cands:
            e = s + len(n)
            if e <= tlen and text[s:e].lower() == n and (e == tlen or text[e] not in _ASCII_ALNUM):
                out.append((s, e))
                limit = e
                break
    return out


# --------------------------------------------------------------------------
# Pseudonym tables
# --------------------------------------------------------------------------


class NameTable:
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.fwd: dict[str, str] = {}   # original (lower) -> pseudo
        self.rev: dict[str, str] = {}   # pseudo -> original (as first seen)
        self.n = 0

    def get(self, orig: str, avoid: set[str]) -> str:
        key = orig.lower()
        p = self.fwd.get(key)
        if p:
            return p
        while True:
            self.n += 1
            cand = f"{self.prefix}{self.n:02d}"
            if cand not in avoid and cand not in self.rev:
                break
        self.fwd[key] = cand
        self.rev[cand] = orig
        return cand


class OrgTable:
    """Organisation-level names: DNS suffixes (orgNN.example) and configured strings."""

    def __init__(self):
        self.n = 0
        self.suffix_fwd: dict[str, str] = {}
        self.str_fwd: dict[str, str] = {}
        self.rev_suffix: dict[str, str] = {}
        self.rev_str: dict[str, str] = {}

    def _new(self, avoid: set[str]) -> str:
        while True:
            self.n += 1
            cand = f"org{self.n:02d}"
            if cand not in avoid and cand not in self.rev_suffix and cand not in self.rev_str:
                return cand

    def suffix(self, suf: str, avoid: set[str]) -> str:
        k = suf.lower()
        p = self.suffix_fwd.get(k)
        if p:
            return p
        first = k.split(".")[0]
        p = self.str_fwd.get(first)
        if not p or p in self.rev_suffix:
            p = self._new(avoid)
        self.suffix_fwd[k] = p
        self.rev_suffix[p] = k
        return p

    def string(self, s: str, avoid: set[str]) -> str:
        k = s.lower()
        p = self.str_fwd.get(k)
        if p:
            return p
        p = None
        for suf, sp in self.suffix_fwd.items():
            if suf.split(".")[0] == k and sp not in self.rev_str:
                p = sp
                break
        if p is None:
            p = self._new(avoid)
        self.str_fwd[k] = p
        self.rev_str[p] = s
        return p

    def bare_rev(self, p: str) -> str | None:
        p = p.lower()
        if p in self.rev_str:
            return self.rev_str[p]
        if p in self.rev_suffix:
            return self.rev_suffix[p].split(".")[0]
        return None


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------


class Session:
    def __init__(self, cfg: Config | None = None, key: bytes | None = None):
        self.key = key or _secrets.token_bytes(32)
        self.host = NameTable("host")
        self.zone = NameTable("zone")
        self.user = NameTable("user")
        self.name = NameTable("name")
        self.org = OrgTable()
        self.ip_originals: set[str] = set()
        self.ip_rev: dict[str, set[str]] = {}
        self.issued24: set[int] = set()
        self.issued_nets: set[tuple[int, int]] = set()
        self.secret_ids: dict[str, str] = {}
        self.secret_counts: dict[str, int] = {}
        self.secret_values: set[str] = set()   # memory only, never persisted
        self.learned_hosts: set[str] = set()
        self.learned_users: set[str] = set()
        self.seen: set[str] = set()
        self.apply_config(cfg or Config())

    # ---------------- configuration ----------------
    def apply_config(self, cfg: Config) -> None:
        self.cfg = cfg
        self.ipmap = IPMapper(self.key, cfg.ip_keep)
        self.hosts_keep = HOST_STOP | set(cfg.hosts_keep)
        self.users_keep = USER_KEEP | set(cfg.users_keep)
        self.suffixes = sorted({s.lower() for s in cfg.suffixes if s}, key=len, reverse=True)
        if self.suffixes:
            alt = "|".join(re.escape(s) for s in self.suffixes)
            self.fqdn_re = re.compile(
                rf"(?i)(?<![A-Za-z0-9\-_])(?P<labels>(?:{LABEL}\.)*)(?P<suf>{alt})(?![A-Za-z0-9\-])"
            )
        else:
            self.fqdn_re = None
        kws = KW_BASE + [re.escape(k) for k in cfg.secret_keys]
        kw = "(?:" + "|".join(kws) + ")"
        key = rf"[A-Za-z0-9_.\-]*?{kw}"
        self.assign_re = re.compile(
            rf"(?<![A-Za-z0-9_.\-])(?P<k>{key})(?![A-Za-z0-9_.\-])[\"']?"
            rf"(?P<sep>[ \t]*(?:=>|[:=])[ \t]*)"
            rf"(?:\"(?P<v1>[^\"\n]*)\"|'(?P<v2>[^'\n]*)'|(?P<v3>[^\s,;&}}\])\"'<>]+))",
            re.IGNORECASE,
        )
        self.line_re = re.compile(
            rf"(?im)^(?P<pre>[ \t]*(?:[#;][ \t]*)?-?)(?P<k>{key})(?![A-Za-z0-9_.\-])[ \t]+"
            rf"(?P<v>[^\s#;]+)[ \t]*(?:[#;].*)?$"
        )
        self.strings = sorted({s for s in cfg.strings if len(s) >= 2}, key=len, reverse=True)
        self.strings_re = (
            re.compile("|".join(re.escape(s) for s in self.strings), re.IGNORECASE)
            if self.strings
            else None
        )
        for h in cfg.hostnames:
            if h.lower() not in self.hosts_keep:
                self.learned_hosts.add(h.lower())
        for u in cfg.users:
            if u.lower() not in self.users_keep:
                self.learned_users.add(u.lower())

    # ---------------- helpers ----------------
    def _seen_update(self, text: str) -> None:
        self.seen.update(t.lower() for t in TOKEN_SPLIT_RE.findall(text))

    def _suffix_of(self, domain: str) -> str | None:
        d = domain.lower().rstrip(".")
        for s in self.suffixes:
            if d == s or d.endswith("." + s):
                return s
        return None

    def _learn_host(self, h: str) -> None:
        h = h.strip().strip(".,;:'\"[]()")
        if not h:
            return
        if IPV4_RE.fullmatch(h):
            return
        if "." in h:
            if self._suffix_of(h):
                h = h.split(".")[0]
            else:
                return
        low = h.lower()
        if (
            len(low) >= 3
            and VALID_HOST_RE.match(h)
            and not low.isdigit()
            and low not in self.hosts_keep
            and not PSEUDO_TOKEN_RE.match(low)
        ):
            self.learned_hosts.add(low)

    def _learn_user(self, u: str) -> None:
        u = u.strip().strip(".,;:'\"[]()")
        if "@" in u:
            u = u.split("@")[0]
        low = u.lower()
        if (
            len(low) >= 2
            and VALID_USER_RE.match(u)
            and not low.isdigit()
            and not HEXBLOB_RE.match(u)
            and low not in self.users_keep
            and not low.startswith("systemd-")
            and not PSEUDO_TOKEN_RE.match(low)
        ):
            self.learned_users.add(low)

    def _learn(self, text: str) -> None:
        for m in SYSLOG_HOST_RE.finditer(text):
            self._learn_host(m.group("h"))
        for m in PROMPT_RE.finditer(text):
            self._learn_host(m.group("h") or m.group("h2"))
            self._learn_user(m.group("u") or m.group("u2"))
        for m in ETC_HOSTS_RE.finditer(text):
            for n in m.group("names").split():
                self._learn_host(n)
        for m in SSH_HOST_RE.finditer(text):
            for n in m.group("names").split():
                if "*" not in n and "?" not in n:
                    self._learn_host(n)
        for rx in (HOST_KV_RE, RSYSLOG_RE, URI_HOST_RE, NFS_RE):
            for m in rx.finditer(text):
                h = m.group("h") or m.groupdict().get("h2")
                if h:
                    self._learn_host(h)
        if self.fqdn_re:
            for m in self.fqdn_re.finditer(text):
                labels = [x for x in m.group("labels").split(".") if x]
                if labels:
                    self._learn_host(labels[0])
        for rx in USER_LEARN_RES:
            for m in rx.finditer(text):
                gd = m.groupdict()
                for g in ("u", "u2"):
                    if gd.get(g):
                        self._learn_user(gd[g])
                if gd.get("list"):
                    for item in re.split(r"[\s,]+", gd["list"]):
                        if item:
                            self._learn_user(item)

    # ---------------- makers ----------------
    def _secret(self, kind: str, value: str) -> str:
        core = value.strip()
        lead = value[: len(value) - len(value.lstrip())]
        trail = value[len(value.rstrip()):]
        hid = hmac.new(self.key, f"{kind}\0{core}".encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()
        ph = self.secret_ids.get(hid)
        if ph is None:
            n = self.secret_counts.get(kind, 0) + 1
            self.secret_counts[kind] = n
            ph = f"<{kind}_{n:02d}>"
            self.secret_ids[hid] = ph
        self.secret_values.add(core)
        return lead + ph + trail

    def _ip_record(self, orig_bare: str, q: int, kind: str, nl: int | None) -> str:
        pbare = int2ip(q)
        self.ip_originals.add(orig_bare)
        self.ip_rev.setdefault(pbare, set()).add(orig_bare)
        if kind == "host":
            self.issued24.add(q >> 8)
        else:
            self.issued_nets.add((q, nl))
        return pbare

    def _map_labels(self, labels: list[str]) -> list[str]:
        out = []
        for i, lab in enumerate(labels):
            low = lab.lower()
            if lab.startswith("_") or low in self.hosts_keep or low.isdigit():
                out.append(lab)
            elif i == 0:
                if low in self.zone.fwd:
                    out.append(self.zone.fwd[low])
                else:
                    out.append(self.host.get(lab, self.seen))
                    self._learn_host(lab)
            else:
                out.append(self.zone.get(lab, self.seen))
        return out

    def _map_domain(self, domain: str) -> list[str] | None:
        suf = self._suffix_of(domain)
        if not suf:
            return None
        d = domain.rstrip(".")
        head = d[: len(d) - len(suf)].rstrip(".")
        labels = [x for x in head.split(".") if x] if head else []
        return self._map_labels(labels) + [self.org.suffix(suf, self.seen), "example"]

    # ---------------- candidate generation ----------------
    def _candidates(self, text: str, nested: bool) -> list[Cand]:
        C: list[Cand] = []
        add = C.append

        def secret_cand(m, group, kind, prio=P_SECRET):
            s, e = m.span(group)
            v = text[s:e]
            add(Cand(s, e, prio, kind, lambda v=v, k=kind: self._secret(k, v), KIND_LABEL[kind]))

        def user_cand(s, e, prio):
            u = text[s:e]
            if not u or u.lower() in self.users_keep or not VALID_USER_RE.match(u):
                return
            add(Cand(s, e, prio, "user", lambda u=u: self._user_pseudo(u), KIND_LABEL["user"]))

        def value_ok(v: str) -> bool:
            s = v.strip()
            if not s:
                return False
            low = s.lower()
            if low in SECRET_VALUE_SKIP:
                return False
            if ENV_REF_RE.match(s) or s.startswith(("{{", "${", "%(", "%{", "[", "<", "!vault")):
                return False
            if s.startswith(("/", "~/", "./", "../")) or "://" in s:
                return False
            if set(s) <= set("*xX"):
                return False
            return True

        # --- blocks
        for m in OVPN_RE.finditer(text):
            kind = "CERT" if m.group("tag") in ("cert", "ca", "extra-certs", "peer-fingerprint") else "KEY"
            if m.group("v").strip():
                secret_cand(m, "v", kind, P_BLOCK)
        for m in PEM_RE.finditer(text):
            label = m.group("label").upper()
            kind = "KEY" if ("PRIVATE" in label or "STATIC KEY" in label) else "CERT"
            if m.group("v").strip():
                secret_cand(m, "v", kind, P_BLOCK)

        # --- secrets
        for m in self.assign_re.finditer(text):
            g = "v1" if m.group("v1") is not None else "v2" if m.group("v2") is not None else "v3"
            if m.group("k").lower().lstrip("-") not in NGINX_PASS_KEYS and value_ok(m.group(g)):
                secret_cand(m, g, "SECRET")
        for m in self.line_re.finditer(text):
            if m.group("k").lower().lstrip("-") not in NGINX_PASS_KEYS and value_ok(m.group("v")):
                secret_cand(m, "v", "SECRET")
        for rx in (URI_CRED_RE, NETRC_RE, SASL_RE, CLI_U_RE):
            for m in rx.finditer(text):
                if value_ok(m.group("v")):
                    secret_cand(m, "v", "SECRET")
                user_cand(*m.span("u"), P_SECRET)
        for rx in (AUTH_HDR_RE, PSK_RE):
            for m in rx.finditer(text):
                secret_cand(m, "v", "SECRET")
        for m in CLI_PW_RE.finditer(text):
            for g in ("v", "v2", "v3"):
                if m.group(g) and value_ok(m.group(g)):
                    secret_cand(m, g, "SECRET")
        for m in SNMP_RE.finditer(text):
            for g in ("v", "v2"):
                if m.group(g):
                    secret_cand(m, g, "SECRET")
        for rx in (JWT_RE, TOKEN_RE):
            for m in rx.finditer(text):
                secret_cand(m, 0, "SECRET")
        for m in HASH_RE.finditer(text):
            secret_cand(m, 0, "HASH")
        for m in PAN_RE.finditer(text):
            digits = re.sub(r"[ \-]", "", m.group(0))
            if 13 <= len(digits) <= 19 and digits[0] in "23456" and _luhn(digits):
                secret_cand(m, 0, "PAN")

        # --- encoded audit fields
        if not nested:
            for m in HEX_AUDIT_RE.finditer(text):
                v = m.group("v")
                if len(v) % 2 == 0:
                    s, e = m.span("v")
                    add(Cand(s, e, P_HEX, "hex", lambda v=v: self._hex(v), KIND_LABEL["hex"]))

        # --- reverse DNS zones
        for m in INADDR_RE.finditer(text):
            octs = [int(x) for x in m.group("v").rstrip(".").split(".")]
            if all(o <= 255 for o in octs):
                s, e = m.span("v")
                add(Cand(s, e, P_INADDR, "inaddr", lambda o=octs: self._inaddr(o), KIND_LABEL["inaddr"]))

        # --- LDAP DN with our domain
        for m in DN_DC_RE.finditer(text):
            v = m.group("v")
            comps = re.split(r"[ \t]*,[ \t]*", v)
            dom = ".".join(c.split("=", 1)[1] for c in comps)
            if self._suffix_of(dom):
                add(Cand(m.start("v"), m.end("v"), P_DN, "dn", lambda v=v: self._dn(v), KIND_LABEL["dn"]))

        # --- FQDN under our suffixes
        if self.fqdn_re:
            for m in self.fqdn_re.finditer(text):
                whole = m.group(0)
                add(Cand(m.start(), m.end(), P_FQDN, "fqdn", lambda w=whole: self._fqdn(w), KIND_LABEL["fqdn"]))

        # --- IPv4
        for m in IPV4_RE.finditer(text):
            tok = m.group(0)
            bare, _, ls = tok.partition("/")
            a = ip2int(bare)
            L = int(ls) if ls else None
            if L is None:
                mm = MASK_AFTER_RE.match(text, m.end())
                if mm:
                    mv = ip2int(mm.group(1))
                    if is_netmask(mv):
                        L = mask_len(mv)
            if self.ipmap.is_kept(a):
                continue
            add(Cand(m.start(), m.end(), P_IP, "ip",
                     lambda bare=bare, a=a, L=L, ls=ls: self._ip(bare, a, L, ls), KIND_LABEL["ip"]))

        # --- user parts of e-mail / principals, LDAP values
        for m in EMAIL_LOCAL_RE.finditer(text):
            user_cand(*m.span("v"), P_LOCAL)
        for rx in (DN_VAL_RE, LDAP_FILTER_RE):
            for m in rx.finditer(text):
                a = m.group("a").lower()
                v = m.group("v").strip()
                if not v:
                    continue
                s = m.start("v") + (len(m.group("v")) - len(m.group("v").lstrip()))
                e = s + len(v)
                if a == "cn" and v.lower() not in self.learned_users:
                    if v.lower() in CN_KEEP or "." in v:
                        continue
                    add(Cand(s, e, P_LOCAL, "name",
                             lambda v=v: _case(v, self.name.get(v, self.seen)), KIND_LABEL["name"]))
                else:
                    user_cand(s, e, P_LOCAL)

        # --- organisation / location in certificate subjects
        for lm in X509_SUBJ_LINE_RE.finditer(text):
            line = lm.group(0)
            for fm in X509_FIELD_RE.finditer(line):
                v = fm.group("v")
                if not v or self._suffix_of(v) or IPV4_RE.fullmatch(v):
                    continue
                s0 = lm.start() + fm.start("v")
                add(Cand(s0, s0 + len(v), P_LOCAL, "string",
                         lambda v=v: _case(v, self.org.string(v, self.seen)), KIND_LABEL["string"]))

        # --- person names (LDIF cn/sn/givenName..., passwd GECOS)
        for m in PERSON_RE.finditer(text):
            g = "v" if m.group("v") is not None else "g"
            v = m.group(g).strip()
            if (not v or not re.search(r"[A-Za-z]", v) or v.lower() in CN_KEEP
                    or v.lower() in self.users_keep or "." in v or "=" in v):
                continue
            s0 = m.start(g) + (len(m.group(g)) - len(m.group(g).lstrip()))
            add(Cand(s0, s0 + len(v), P_LOCAL, "name",
                     lambda v=v: self._person(v), KIND_LABEL["name"]))

        # --- learned / configured names
        for s0, e0 in find_names(text, self.learned_hosts):
            h = text[s0:e0]
            add(Cand(s0, e0, P_HOST, "host",
                     lambda h=h: _case(h, self._host_pseudo(h)), KIND_LABEL["host"]))
        for s0, e0 in find_names(text, self.learned_users):
            u = text[s0:e0]
            add(Cand(s0, e0, P_USER, "user", lambda u=u: self._user_pseudo(u), KIND_LABEL["user"]))
        if self.strings_re:
            for m in self.strings_re.finditer(text):
                s = m.group(0)
                add(Cand(m.start(), m.end(), P_STR, "string",
                         lambda s=s: _case(s, self.org.string(s, self.seen)), KIND_LABEL["string"]))
        return C

    def _user_pseudo(self, u: str) -> str:
        self._learn_user(u)
        return _case(u, self.user.get(u, self.seen))

    def _person(self, v: str) -> str:
        """A person name (LDIF cn/sn, GECOS) is masked as a whole."""
        low = v.lower()
        if low in self.learned_users or low in self.user.fwd:
            return self._user_pseudo(v)
        return _case(v, self.name.get(v, self.seen))

    def _host_pseudo(self, h: str) -> str:
        low = h.lower()
        if low in self.host.fwd:
            return self.host.fwd[low]
        if low in self.zone.fwd:
            return self.zone.fwd[low]
        return self.host.get(h, self.seen)

    def _ip(self, bare: str, a: int, L: int | None, ls: str) -> str:
        q, kind, nl = self.ipmap.forward(a, L)
        if kind == "keep":
            return bare + (f"/{ls}" if ls else "")
        pbare = self._ip_record(bare, q, kind, nl)
        return pbare + (f"/{ls}" if ls else "")

    def _inaddr(self, octs: list[int]) -> str:
        n = len(octs)
        fwd = list(reversed(octs)) + [0] * (4 - n)
        a = (fwd[0] << 24) | (fwd[1] << 16) | (fwd[2] << 8) | fwd[3]
        L = 8 * n if n < 4 else None
        q, kind, nl = self.ipmap.forward(a, L)
        if kind != "keep":
            self._ip_record(int2ip(a), q, kind, nl)
        qo = [int(x) for x in int2ip(q).split(".")][:n]
        return ".".join(str(x) for x in reversed(qo)) + "."

    def _dn(self, v: str) -> str:
        comps = re.split(r"([ \t]*,[ \t]*)", v)
        parts = comps[0::2]
        seps = comps[1::2]
        keyname = parts[0].split("=", 1)[0]
        dom = ".".join(p.split("=", 1)[1] for p in parts)
        labels = self._map_domain(dom)
        if labels is None:
            return v
        upper = _case(dom, "x") == "X"
        sep = seps[0] if seps else ","
        return sep.join(f"{keyname}={lab.upper() if upper else lab}" for lab in labels)

    def _fqdn(self, whole: str) -> str:
        labels = self._map_domain(whole)
        if labels is None:
            return whole
        out = ".".join(labels)
        letters = [c for c in whole if c.isalpha()]
        if letters and all(c.isupper() for c in letters):
            out = out.upper()
        return out

    def _hex(self, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError:
            return v
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (0, 9, 10, 13))
        if printable < len(raw) * 0.9:
            return v
        decoded = raw.decode("utf-8", "surrogateescape")
        out, _, _ = self._mask_core(decoded, nested=True)
        if out == decoded:
            return v
        return out.encode("utf-8", "surrogateescape").hex().upper()

    # ---------------- resolution and rendering ----------------
    @staticmethod
    def _resolve(cands: list[Cand], n: int) -> list[Cand]:
        cands.sort(key=lambda c: (c.prio, -(c.end - c.start), c.start))
        occupied = bytearray(n + 1)
        accepted: list[Cand] = []
        for c in cands:
            if c.end <= c.start or occupied.find(1, c.start, c.end) != -1:
                continue
            occupied[c.start:c.end] = b"\x01" * (c.end - c.start)
            accepted.append(c)
        accepted.sort(key=lambda c: c.start)
        return accepted

    def _render(self, text: str, accepted: list[Cand]):
        out: list[str] = []
        in_spans: list[Span] = []
        out_spans: list[Span] = []
        pos = 0
        opos = 0
        for c in accepted:
            out.append(text[pos:c.start])
            opos += c.start - pos
            orig = text[c.start:c.end]
            rep = c.make()
            out.append(rep)
            if rep != orig:
                kind = "secret" if c.kind in SECRET_KINDS else "masked"
                in_spans.append(Span(c.start, c.end, kind, c.note))
                out_spans.append(Span(opos, opos + len(rep), kind, c.note))
            opos += len(rep)
            pos = c.end
        out.append(text[pos:])
        return "".join(out), in_spans, out_spans

    def _mask_core(self, text: str, nested: bool = False):
        self._seen_update(text)
        self._learn(text)
        result = (text, [], [])
        for _ in range(4):
            before = (len(self.learned_hosts), len(self.learned_users))
            result = self._render(text, self._resolve(self._candidates(text, nested), len(text)))
            if (len(self.learned_hosts), len(self.learned_users)) == before:
                break
        return result

    # ---------------- public API ----------------
    def issued_pseudonyms(self) -> set[str]:
        s = set(self.host.rev) | set(self.zone.rev) | set(self.user.rev) | set(self.name.rev)
        s |= set(self.org.rev_suffix) | set(self.org.rev_str)
        return s

    def mask(self, text: str) -> Result:
        pre_issued = self.issued_pseudonyms()
        out, in_spans, out_spans = self._mask_core(text)
        res = Result(out, in_spans, out_spans)
        # Real tokens that look exactly like pseudonyms issued earlier.
        if pre_issued:
            for m in TOKEN_SPLIT_RE.finditer(text):
                t = m.group(0).lower()
                if t in pre_issued:
                    res.findings.append(Finding("in", m.start(), m.end(), "warn", "input_collides",
                                                {"tok": m.group(0)}))
        res.findings.extend(self.leak_check(out))
        return res

    def leak_check(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        issued = self.issued_pseudonyms()
        # IP addresses
        for m in LEAK_IP_RE.finditer(text):
            ip = m.group(0)
            if ip in self.ip_rev:
                continue           # a pseudonym issued by this session
            if any(int(o) > 255 for o in ip.split(".")):
                continue
            if ip in self.ip_originals:
                found.append(Finding("out", m.start(), m.end(), "error", "leak_ip", {"ip": ip}))
                continue
            a = ip2int(ip)
            if self.ipmap.is_kept(a) or self._derivable(a, None):
                continue
            found.append(Finding("out", m.start(), m.end(), "error", "unmasked_ip", {"ip": ip}))
        # substrings: suffixes and configured strings
        subs = {s.lower() for s in self.suffixes} | {s.lower() for s in self.strings if len(s) >= 3}
        if subs:
            alt = "|".join(re.escape(x) for x in sorted(subs, key=len, reverse=True))
            for m in re.finditer(alt, text, re.IGNORECASE):
                found.append(Finding("out", m.start(), m.end(), "error", "leak_string", {"v": m.group(0)}))
        # names with relaxed boundaries
        names = set()
        names |= self.learned_hosts | self.learned_users
        names |= set(self.host.fwd) | set(self.user.fwd) | set(self.name.fwd)
        for s in self.suffixes:
            first = s.split(".")[0]
            if first not in self.hosts_keep:
                names.add(first)
        names = {n for n in names if len(n) >= 3 and n not in issued
                 and n not in self.hosts_keep and n not in self.users_keep}
        for s0, e0 in find_names(text, names):
            found.append(Finding("out", s0, e0, "error", "leak_name", {"v": text[s0:e0]}))
        # secrets (plaintext kept in memory only)
        for v in self.secret_values:
            if len(v) < 4:
                continue
            start = 0
            while True:
                i = text.find(v, start)
                if i < 0:
                    break
                found.append(Finding("out", i, i + len(v), "error", "leak_secret"))
                start = i + 1
        found.sort(key=lambda f: (f.start, -(f.end - f.start)))
        # drop findings nested inside a longer one (e.g. "acme" inside "acme.lan")
        result: list[Finding] = []
        for f in found:
            if result and f.start >= result[-1].start and f.end <= result[-1].end:
                continue
            result.append(f)
        return result

    # ---------------- reverse ----------------
    def _derivable(self, q: int, L: int | None) -> bool:
        kind, nl = self.ipmap.shape(q, L)
        if kind == "host":
            if (q >> 8) in self.issued24:
                return True
            return any((q >> (32 - l2)) == (n2 >> (32 - l2)) for n2, l2 in self.issued_nets)
        items = [(p << 8, 24) for p in self.issued24] + list(self.issued_nets)
        for n2, l2 in items:
            m = min(nl, l2)
            if m >= 16 and (q >> (32 - m)) == (n2 >> (32 - m)):
                return True
        return False

    def _rev_label(self, lab: str):
        """-> (text, status) status: restored | keep | unknown"""
        low = lab.lower()
        if PSEUDO_TOKEN_RE.match(low):
            for t in (self.host, self.zone):
                if low in t.rev:
                    return t.rev[low], "restored"
            return lab, "unknown"
        return lab, "keep"

    def unmask(self, text: str) -> Result:
        res = Result("")
        out: list[str] = []
        pos = 0
        opos = 0

        def emit(m_start, m_end, rep, kind, note, finding_level=None, code=None, args=None):
            nonlocal pos, opos
            out.append(text[pos:m_start])
            opos += m_start - pos
            out.append(rep)
            if kind:
                res.in_spans.append(Span(m_start, m_end, kind, note))
                res.out_spans.append(Span(opos, opos + len(rep), kind, note))
                if finding_level:
                    res.findings.append(Finding("out", opos, opos + len(rep), finding_level, code,
                                                args or {}))
            opos += len(rep)
            pos = m_end

        for m in UNMASK_RE.finditer(text):
            g = m.lastgroup
            tok = m.group(0)
            if g == "ph":
                emit(m.start(), m.end(), tok, "secret", "secret", "warn", "secret_placeholder", {"tok": tok})
            elif g in ("ip", "inaddr"):
                if g == "ip":
                    bare, _, ls = tok.partition("/")
                    q = ip2int(bare)
                    L = int(ls) if ls else None
                    if L is None:
                        mm = MASK_AFTER_RE.match(text, m.end())
                        if mm and is_netmask(ip2int(mm.group(1))):
                            L = mask_len(ip2int(mm.group(1)))
                    n_oct = None
                else:
                    octs = [int(x) for x in tok.split("in-addr")[0].rstrip(".").split(".")]
                    if any(o > 255 for o in octs):
                        continue
                    n_oct = len(octs)
                    fwd = list(reversed(octs)) + [0] * (4 - n_oct)
                    q = (fwd[0] << 24) | (fwd[1] << 16) | (fwd[2] << 8) | fwd[3]
                    L = 8 * n_oct if n_oct < 4 else None
                    bare, ls = int2ip(q), ""
                if self.ipmap.is_kept(q):
                    continue
                r, _, _ = self.ipmap.reverse(q, L)
                origs = self.ip_rev.get(bare)
                status = None
                if origs:
                    rs = int2ip(r)
                    if rs in origs:
                        real, status = rs, "restored"
                    elif len(origs) == 1:
                        real, status = next(iter(origs)), "restored"
                    else:
                        real, status = rs, "ambiguous"
                elif self._derivable(q, L):
                    real, status = int2ip(r), "derived"
                if status is None:
                    emit(m.start(), m.end(), tok, "unknown", "ip", "warn", "ip_unknown", {"tok": tok})
                    continue
                if g == "ip":
                    rep = real + (f"/{ls}" if ls else "")
                else:
                    ro = real.split(".")[:n_oct]
                    rep = ".".join(reversed(ro)) + ".in-addr.arpa"
                if status == "restored":
                    emit(m.start(), m.end(), rep, "restored", "ip")
                elif status == "derived":
                    emit(m.start(), m.end(), rep, "derived", "ip", "info", "ip_derived", {"tok": tok, "rep": rep})
                else:
                    emit(m.start(), m.end(), rep, "ambiguous", "ip", "warn", "ip_ambiguous",
                         {"tok": tok, "cands": ", ".join(sorted(origs))})
            elif g == "dn":
                comps = re.split(r"([ \t]*,[ \t]*)", tok)
                parts, seps = comps[0::2], comps[1::2]
                vals = [p.split("=", 1)[1] for p in parts]
                if len(vals) < 2 or vals[-1].lower() != "example" or not re.fullmatch(r"(?i)org\d{2,}", vals[-2]):
                    continue
                suf = self.org.rev_suffix.get(vals[-2].lower())
                if not suf:
                    emit(m.start(), m.end(), tok, "unknown", "dn", "warn", "domain_unknown", {"tok": tok})
                    continue
                labels_out, unknown = [], False
                for v in vals[:-2]:
                    t, st = self._rev_label(v)
                    unknown |= st == "unknown"
                    labels_out.append(t)
                labels_out += suf.split(".")
                keyname = parts[0].split("=", 1)[0]
                upper = _case(".".join(vals), "x") == "X"
                sep = seps[0] if seps else ","
                rep = sep.join(f"{keyname}={x.upper() if upper else x}" for x in labels_out)
                if unknown:
                    emit(m.start(), m.end(), rep, "unknown", "dn", "warn", "labels_unknown", {"tok": tok})
                else:
                    emit(m.start(), m.end(), rep, "restored", "dn")
            elif g == "fqdn":
                org = m.group("forg").lower()
                suf = self.org.rev_suffix.get(org)
                if not suf:
                    emit(m.start(), m.end(), tok, "unknown", "fqdn", "warn", "domain_unknown", {"tok": tok})
                    continue
                labels = [x for x in m.group("flabels").split(".") if x]
                labels_out, unknown = [], False
                for lab in labels:
                    t, st = self._rev_label(lab)
                    unknown |= st == "unknown"
                    labels_out.append(t)
                rep = ".".join(labels_out + [suf])
                letters = [c for c in tok if c.isalpha()]
                if letters and all(c.isupper() for c in letters):
                    rep = rep.upper()
                if unknown:
                    emit(m.start(), m.end(), rep, "unknown", "fqdn", "warn", "labels_unknown", {"tok": tok})
                else:
                    emit(m.start(), m.end(), rep, "restored", "fqdn")
            elif g == "tok":
                low = tok.lower()
                pref = re.match(r"[a-z]+", low).group(0)
                orig = None
                if pref == "host":
                    orig = self.host.rev.get(low)
                elif pref == "zone":
                    orig = self.zone.rev.get(low)
                elif pref == "user":
                    orig = self.user.rev.get(low)
                elif pref == "name":
                    orig = self.name.rev.get(low)
                elif pref == "org":
                    orig = self.org.bare_rev(low)
                if orig is None:
                    emit(m.start(), m.end(), tok, "unknown", pref, "warn", "pseudo_unknown", {"tok": tok})
                else:
                    emit(m.start(), m.end(), _uncase(tok, orig), "restored", pref)
        out.append(text[pos:])
        res.text = "".join(out)
        return res

    # ---------------- info ----------------
    def stats(self) -> dict[str, int]:
        """Counts by category code; localise keys with i18n "stat.<code>"."""
        return {
            "ip": len(self.ip_originals),
            "domains": len(self.org.rev_suffix),
            "hosts": len(self.host.fwd),
            "zones": len(self.zone.fwd),
            "users": len(self.user.fwd),
            "names": len(self.name.fwd),
            "strings": len(self.org.rev_str),
            "secrets": len(self.secret_ids),
        }

    def mapping_rows(self) -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        for pbare, origs in sorted(self.ip_rev.items()):
            for o in sorted(origs):
                rows.append((_t("cat.ip"), o, pbare))
        for p, s in sorted(self.org.rev_suffix.items()):
            rows.append((_t("cat.domain"), s, f"{p}.example"))
        for p, s in sorted(self.org.rev_str.items()):
            rows.append((_t("cat.string"), s, p))
        for code, table in (("host", self.host), ("zone", self.zone), ("user", self.user),
                            ("name", self.name)):
            for p, o in sorted(table.rev.items()):
                rows.append((_t("cat." + code), o, p))
        for ph in sorted(self.secret_ids.values()):
            rows.append((_t("cat.secret"), _t("cat.secret_value"), ph))
        return rows

    # ---------------- persistence (CLI, tmpfs) ----------------
    def to_dict(self) -> dict:
        def nt(t: NameTable):
            return {"fwd": t.fwd, "rev": t.rev, "n": t.n}
        return {
            "v": 1,
            "key": self.key.hex(),
            "host": nt(self.host), "zone": nt(self.zone), "user": nt(self.user), "name": nt(self.name),
            "org": {"n": self.org.n, "suffix_fwd": self.org.suffix_fwd, "str_fwd": self.org.str_fwd,
                    "rev_suffix": self.org.rev_suffix, "rev_str": self.org.rev_str},
            "ip_originals": sorted(self.ip_originals),
            "ip_rev": {k: sorted(v) for k, v in self.ip_rev.items()},
            "issued24": sorted(self.issued24),
            "issued_nets": sorted([list(x) for x in self.issued_nets]),
            "secret_ids": self.secret_ids, "secret_counts": self.secret_counts,
            "learned_hosts": sorted(self.learned_hosts), "learned_users": sorted(self.learned_users),
            "seen": sorted(self.seen),
        }

    @classmethod
    def from_dict(cls, d: dict, cfg: Config) -> "Session":
        s = cls(cfg, bytes.fromhex(d["key"]))
        for name in ("host", "zone", "user", "name"):
            t: NameTable = getattr(s, name)
            t.fwd, t.rev, t.n = d[name]["fwd"], d[name]["rev"], d[name]["n"]
        o = d["org"]
        s.org.n, s.org.suffix_fwd, s.org.str_fwd = o["n"], o["suffix_fwd"], o["str_fwd"]
        s.org.rev_suffix, s.org.rev_str = o["rev_suffix"], o["rev_str"]
        s.ip_originals = set(d["ip_originals"])
        s.ip_rev = {k: set(v) for k, v in d["ip_rev"].items()}
        s.issued24 = set(d["issued24"])
        s.issued_nets = {tuple(x) for x in d["issued_nets"]}
        s.secret_ids, s.secret_counts = d["secret_ids"], d["secret_counts"]
        s.learned_hosts |= set(d["learned_hosts"])
        s.learned_users |= set(d["learned_users"])
        s.seen = set(d["seen"])
        return s
