"""Local configuration: what is sensitive in *your* infrastructure.

The file lives only on your machine (default ~/.config/llmscrub/config.toml,
mode 0600).  Never paste its contents into an AI chat.
"""

from __future__ import annotations

import ipaddress
import os
import stat
import tomllib
from dataclasses import dataclass, field

from .i18n import get_lang, t

DEFAULT_PATH = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
    "llmscrub",
    "config.toml",
)


@dataclass
class Config:
    suffixes: list[str] = field(default_factory=list)      # internal DNS suffixes
    hostnames: list[str] = field(default_factory=list)     # short host names
    hosts_keep: list[str] = field(default_factory=list)    # host labels not to mask
    users: list[str] = field(default_factory=list)         # user names to mask
    users_keep: list[str] = field(default_factory=list)    # user names not to mask
    strings: list[str] = field(default_factory=list)       # company / project names
    ip_keep: list[str] = field(default_factory=list)       # IPs / CIDRs not to mask
    secret_keys: list[str] = field(default_factory=list)   # extra secret key names
    path: str | None = None
    warnings: list[str] = field(default_factory=list)


def _strlist(d: dict, key: str, where: str, warnings: list[str]) -> list[str]:
    v = d.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        warnings.append(t("cfg.bad_list", where=where, key=key))
        return []
    return [x.strip() for x in v if x.strip()]


def load_config(path: str | None = None) -> Config:
    path = path or DEFAULT_PATH
    cfg = Config(path=path)
    if not os.path.exists(path):
        cfg.warnings.append(t("cfg.not_found", path=path))
        return cfg
    try:
        st = os.stat(path)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            cfg.warnings.append(t("cfg.perms", path=path))
    except OSError:
        pass
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        cfg.warnings.append(t("cfg.parse_error", path=path, err=exc))
        return cfg
    w = cfg.warnings
    dom = data.get("domains", {})
    hosts = data.get("hosts", {})
    users = data.get("users", {})
    strings = data.get("strings", {})
    ips = data.get("ips", {})
    secrets = data.get("secrets", {})
    cfg.suffixes = [s.lower().strip(".") for s in _strlist(dom, "suffixes", "domains", w)]
    cfg.hostnames = _strlist(hosts, "names", "hosts", w)
    cfg.hosts_keep = [s.lower() for s in _strlist(hosts, "keep", "hosts", w)]
    cfg.users = _strlist(users, "names", "users", w)
    cfg.users_keep = [s.lower() for s in _strlist(users, "keep", "users", w)]
    cfg.strings = _strlist(strings, "values", "strings", w)
    cfg.ip_keep = []
    for item in _strlist(ips, "keep", "ips", w):
        try:
            ipaddress.IPv4Network(item, strict=False)
            cfg.ip_keep.append(item)
        except ValueError:
            w.append(t("cfg.bad_ip", item=item))
    cfg.secret_keys = _strlist(secrets, "extra_keys", "secrets", w)
    return cfg


def example_config(lang: str | None = None) -> str:
    return EXAMPLE_RU if (lang or get_lang()) == "ru" else EXAMPLE_EN


EXAMPLE_EN = '''# llmscrub — local config. Never paste its contents into an AI chat.
# Permissions: chmod 600 this file.

[domains]
# Internal DNS suffixes. Everything ending with them is masked:
# FQDNs, Kerberos realms (ACME.LAN), LDAP DNs (dc=acme,dc=lan), e-mail addresses.
suffixes = ["acme.lan", "acmepay.internal"]

[hosts]
# Short host names to always mask. Most are found automatically
# (FQDNs, syslog prefix, /etc/hosts, shell prompts, fstab, rsyslog, URIs).
names = []
# Labels that should NOT be masked (in addition to the built-in list:
# www, mail, ns1, ldap, prod, ...).
keep = []

[users]
# User names to always mask (others are found in auth.log, sudo, audit,
# passwd/shadow/group, sshd_config, sssd.conf, /home/<user>, ...).
names = []
# Do not mask (in addition to system accounts: root, www-data, sshd, ...).
keep = []

[strings]
# Company, project, NetBIOS domain names etc. — masked as case-insensitive
# substrings, including inside paths such as /etc/ssl/acme-prod/.
values = ["Acme"]

[ips]
# Do not mask: public resolvers and the like. IPv4 addresses or CIDRs.
keep = ["8.8.8.8", "1.1.1.1"]

[secrets]
# Extra key names whose values are treated as secrets.
extra_keys = []
'''

EXAMPLE_RU = '''# llmscrub — локальный конфиг. Не передавайте его содержимое в ИИ.
# Права: chmod 600 этого файла.

[domains]
# Внутренние DNS-суффиксы. Всё, что заканчивается на них, маскируется:
# FQDN, Kerberos-realm (ACME.LAN), LDAP DN (dc=acme,dc=lan), e-mail.
suffixes = ["acme.lan", "acmepay.internal"]

[hosts]
# Короткие имена хостов, которые нужно маскировать всегда. Большинство
# находится автоматически (FQDN, префикс syslog, /etc/hosts, prompt, fstab,
# rsyslog, URI).
names = []
# Метки, которые маскировать не нужно (в дополнение к встроенному списку
# www, mail, ns1, ldap, prod, ...).
keep = []

[users]
# Пользователи, которых нужно маскировать всегда (остальные находятся в
# auth.log, sudo, audit, passwd/shadow/group, sshd_config, sssd.conf, /home/<user> ...).
names = []
# Не маскировать (в дополнение к системным: root, www-data, sshd, ...).
keep = []

[strings]
# Название компании, проектов, NetBIOS-домен и т.п. — маскируются как подстрока
# без учёта регистра, в том числе в путях вида /etc/ssl/acme-prod/.
values = ["Acme"]

[ips]
# Не маскировать: публичные резолверы и т.п. IPv4-адреса или CIDR.
keep = ["8.8.8.8", "1.1.1.1"]

[secrets]
# Дополнительные имена ключей, значения которых считать секретами.
extra_keys = []
'''
