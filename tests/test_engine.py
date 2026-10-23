"""Tests on synthetic data. All values here are invented.

Public addresses in the samples come from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which llmscrub leaves as is
by design. Masking of real public addresses is tested with addresses generated
at run time, so the repository contains no real third-party IPs.
"""

import glob
import os
import random
import re
import unittest

from llmscrub import i18n
from llmscrub.config import Config, example_config, load_config
from llmscrub.engine import Session
from llmscrub.ipmap import IPMapper, int2ip, ip2int

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = load_config(os.path.join(HERE, "test_config.toml"))
SAMPLES = sorted(glob.glob(os.path.join(HERE, "samples", "*")))

# Must never appear in masked output (checked independently of the engine's own leak check).
FORBIDDEN_CI = [
    "acme", "ivanov", "petrova", "svc-backup", "svc-ldap", "app_pay", "deploy", "db01", "web01",
    "ipa01", "mon01", "nfs01", "log01", "vpn01", "payapi", "notify", "maria", "ivan ", "bkp02",
    "payments s.l", "a8f3k2", "my$qlr00t",
]
FORBIDDEN = [
    "10.20.", "192.168.50.", "172.20.5.", "30.20.10.in-addr",
    " 20.10.in-addr", '"20.10.in-addr', "Sup3r", "BindPw", "M41l-P4ss", "R3d1s", "Kp4ss77", "Acm3Mon",
    "4111 1111", "aXZhbm92", "eyJhbGci", "6acef03f", "hR3uYyq0", "aGVsbG8gd29ybGQ", "MIIBszCC",
]


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def expected_restore(orig, res):
    """Original text with irreversible parts (secrets, hex fields) as in the output."""
    out, pos = [], 0
    for si, so in zip(res.in_spans, res.out_spans):
        out.append(orig[pos:si.start])
        if si.kind == "secret" or si.note.startswith("hex"):
            out.append(res.text[so.start:so.end])
        else:
            out.append(orig[si.start:si.end])
        pos = si.end
    out.append(orig[pos:])
    return "".join(out)


def decoded_hex_fields(text):
    out = []
    for m in re.finditer(r"proctitle=([0-9A-F]+)", text):
        out.append(bytes.fromhex(m.group(1)).decode("utf-8", "replace"))
    return "\n".join(out)


class TestSamples(unittest.TestCase):
    def setUp(self):
        self.s = Session(CFG)

    def test_no_leaks_and_roundtrip(self):
        for path in SAMPLES:
            with self.subTest(sample=os.path.basename(path)):
                orig = read(path)
                res = self.s.mask(orig)
                masked = res.text + "\n" + decoded_hex_fields(res.text)
                low = masked.lower()
                for f in FORBIDDEN_CI:
                    self.assertNotIn(f, low, f"leak {f!r}")
                for f in FORBIDDEN:
                    self.assertNotIn(f, masked, f"leak {f!r}")
                errors = [f for f in res.findings if f.level == "error"]
                self.assertEqual(errors, [], [e.message for e in errors])
                back = self.s.unmask(res.text)
                self.assertEqual(back.text, expected_restore(orig, res))
                bad = [f.message for f in back.findings
                       if f.level == "warn" and f.code != "secret_placeholder"]
                self.assertEqual(bad, [])

    def test_consistency_across_files(self):
        out = {os.path.basename(p): self.s.mask(read(p)).text for p in SAMPLES}
        # the same real address gets the same pseudonym in different files
        ip = re.search(r"ListenAddress (\S+)", out["sshd_config"]).group(1)
        self.assertIn(f"{ip} host01", out["net.conf"].replace("  ", " "))
        # /20 from sshd_config == /20 in nftables and the openvpn route
        net = re.search(r"Match Address (\S+?)/20", out["sshd_config"]).group(1)
        self.assertIn(f"{net}/20", out["nftables.conf"])
        self.assertIn(f"route {net} 255.255.240.0", out["openvpn.conf"])

    def test_keep_and_special(self):
        r = self.s.mask("nameserver 8.8.8.8\nlo 127.0.0.1 mask 255.255.255.0 any 0.0.0.0/0\n"
                        "oid 1.3.6.1.4.1.2021.10 ver 1.2.3\n")
        self.assertEqual(r.text, "nameserver 8.8.8.8\nlo 127.0.0.1 mask 255.255.255.0 any 0.0.0.0/0\n"
                                 "oid 1.3.6.1.4.1.2021.10 ver 1.2.3\n")

    def test_pam_and_booleans_untouched(self):
        t = ("password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"
             "password requisite pam_deny.so\nPermitEmptyPasswords no\nPasswordAuthentication yes\n"
             "PASS_MAX_DAYS 90\nldap_default_authtok_type = password\n"
             "Oct 22 09:20:45 srv1 sshd[1]: Failed password for root from 127.0.0.1 port 1 ssh2\n")
        self.assertEqual(self.s.mask(t).text.split("\n")[:6], t.split("\n")[:6])


class TestReverse(unittest.TestCase):
    def setUp(self):
        self.s = Session(CFG)
        self.m = self.s.mask(
            "Oct 22 09:14:01 db01 sshd[1]: Accepted publickey for ivanov from 10.20.17.88 port 1 ssh2\n"
            "allow 10.20.16.0/20; host db01.acme.lan has 10.20.30.15\n")

    def pseudo(self, real):
        q, _, _ = self.s.ipmap.forward(ip2int(real))
        return int2ip(q)

    def test_ai_commands(self):
        p15 = self.pseudo("10.20.30.15")
        gw = p15.rsplit(".", 1)[0] + ".1"           # AI computes the gateway
        ai = (f"ssh ivanov@host01.org01.example\nping -c3 {gw}\nnmap -p22 {p15}\n"
              f"dig @8.8.8.8 host01.org01.example\nsudo -u user01 id\ncat <SECRET_01>\n"
              f"ping 172.31.99.5\nssh host77\n")
        r = self.s.unmask(ai)
        self.assertIn("ssh ivanov@db01.acme.lan", r.text)
        self.assertIn("ping -c3 10.20.30.1", r.text)          # derived
        self.assertIn("nmap -p22 10.20.30.15", r.text)        # restored
        self.assertIn("dig @8.8.8.8 db01.acme.lan", r.text)   # kept public resolver
        self.assertIn("sudo -u ivanov id", r.text)
        self.assertIn("<SECRET_01>", r.text)
        kinds = {r.text[s.start:s.end]: s.kind for s in r.out_spans}
        self.assertEqual(kinds["10.20.30.1"], "derived")
        self.assertEqual(kinds["172.31.99.5"], "unknown")     # invented by the AI
        self.assertEqual(kinds["host77"], "unknown")

    def test_cidr_containment_reverse(self):
        net = int2ip(self.s.ipmap.forward(ip2int("10.20.16.0"), 20)[0])
        r = self.s.unmask(f"ip route add {net}/20 via x\n")
        self.assertIn("10.20.16.0/20", r.text)


class TestIPMapper(unittest.TestCase):
    def test_properties(self):
        import random
        rnd = random.Random(7)
        m = IPMapper(os.urandom(32), keep=["8.8.8.8", "10.99.0.0/16"])
        for _ in range(20000):
            a = rnd.getrandbits(32)
            q, kind, _ = m.forward(a)
            if kind != "keep":
                self.assertEqual(m.classify24(a >> 8), m.classify24(q >> 8))
            if (a & 0xFF) != 0:   # .0 hosts are the documented ambiguous case
                self.assertEqual(m.reverse(q)[0], a)
        # same /24 stays the same /24, last octet kept
        a, b = m.map_host(ip2int("192.168.50.10")), m.map_host(ip2int("192.168.50.200"))
        self.assertEqual(a >> 8, b >> 8)
        self.assertEqual(a & 255, 10)
        # /20 containment
        n = m.map_net(ip2int("10.20.16.0"), 20)
        for h in ("10.20.16.1", "10.20.23.4", "10.20.31.254"):
            self.assertEqual(m.map_host(ip2int(h)) >> 12, n >> 12)
        # pseudonyms never land in a kept range
        for _ in range(3000):
            x = ip2int("10.0.0.0") | rnd.getrandbits(24)
            if (x >> 16) != (ip2int("10.99.0.0") >> 16):
                self.assertNotEqual(m.map_host(x) >> 16, ip2int("10.99.0.0") >> 16)


class TestSecrets(unittest.TestCase):
    def test_same_secret_same_placeholder(self):
        s = Session(Config())
        r = s.mask("password=Qwerty123!\nbackup_password: 'Qwerty123!'\nPGPASSWORD=other1\n")
        self.assertEqual(r.text.count("<SECRET_01>"), 2)
        self.assertIn("<SECRET_02>", r.text)

    def test_private_key_block(self):
        s = Session(Config())
        t = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
        r = s.mask(t)
        self.assertNotIn("b3BlbnNz", r.text)
        self.assertIn("<KEY_01>", r.text)

    def test_leak_check_catches_manual_edit(self):
        s = Session(CFG)
        r = s.mask("host db01.acme.lan user ivanov password=Zx9!longpass\n")
        edited = r.text + "\nps: ivanov on db01, pw Zx9!longpass, ip 10.1.2.3\n"
        found = s.leak_check(edited)
        msgs = [f.message for f in found]
        codes = {f.code for f in found}
        self.assertTrue(any("ivanov" in m for m in msgs))
        self.assertTrue(any("db01" in m for m in msgs))
        self.assertIn("leak_secret", codes)
        self.assertIn("unmasked_ip", codes)                   # 10.1.2.3: never seen, not masked
        self.assertTrue(any("10.1.2.3" in m for m in msgs))

    def test_masked_output_is_clean_for_leak_check(self):
        s = Session(CFG)
        out = s.mask("local-data: \"15.30.20.10.in-addr.arpa. IN PTR db01.acme.lan.\" 10.20.30.15\n").text
        self.assertEqual(s.leak_check(out), [])


class TestPublicAddresses(unittest.TestCase):
    """Real public addresses, generated at run time (never stored in the repo)."""

    @staticmethod
    def random_public(rnd, mapper):
        import ipaddress
        while True:
            a = rnd.getrandbits(32)
            ip = ipaddress.IPv4Address(a)
            if ip.is_global and mapper.classify24(a >> 8)[0] == "public" and (a & 255) not in (0, 255):
                return int2ip(a)

    def test_public_masked_and_restored(self):
        rnd = random.Random(11)
        s = Session(CFG)
        attacker = self.random_public(rnd, s.ipmap)
        ours = self.random_public(rnd, s.ipmap)
        net = ours.rsplit(".", 1)[0] + ".0/24"
        text = (f"Oct 22 09:20:44 db01 sshd[1]: Failed password for invalid user oracle from {attacker} port 1 ssh2\n"
                f"server {{ listen {ours}:443 ssl; }}\nip saddr {net} tcp dport 443 accept\n")
        r = s.mask(text)
        self.assertNotIn(attacker, r.text)
        self.assertNotIn(ours, r.text)
        self.assertNotIn(net, r.text)
        self.assertEqual([f for f in r.findings if f.level == "error"], [])
        # pseudonyms of public addresses are public addresses, same /24 stays the same /24
        p_ours = re.search(r"listen (\S+):443", r.text).group(1)
        p_net = re.search(r"ip saddr (\S+)/24", r.text).group(1)
        self.assertEqual(s.ipmap.classify24(ip2int(p_ours) >> 8)[0], "public")
        self.assertEqual(p_ours.rsplit(".", 1)[0], p_net.rsplit(".", 1)[0])
        self.assertEqual(s.unmask(r.text).text, text)


class TestI18n(unittest.TestCase):
    def tearDown(self):
        i18n.set_lang(None)

    def test_catalogues_match(self):
        en, ru = i18n.MESSAGES["en"], i18n.MESSAGES["ru"]
        self.assertEqual(set(en), set(ru))
        field = re.compile(r"\{(\w+)\}")
        for k in en:
            self.assertEqual(set(field.findall(en[k])), set(field.findall(ru[k])), k)

    def test_all_finding_codes_have_messages(self):
        src = open(os.path.join(HERE, "..", "llmscrub", "engine.py"), encoding="utf-8").read()
        codes = set(re.findall(r'Finding\("(?:in|out)", [^,]+, [^,]+, "\w+", "(\w+)"', src))
        codes |= set(re.findall(r'"(?:warn|info)", "(\w+)"', src))
        self.assertTrue(codes)
        for c in codes:
            self.assertIn("f." + c, i18n.MESSAGES["en"], c)

    def test_detect(self):
        env = dict(os.environ)
        try:
            for var in ("LLMSCRUB_LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
                os.environ.pop(var, None)
            self.assertEqual(i18n.detect(), "en")
            os.environ["LANG"] = "ru_RU.UTF-8"
            self.assertEqual(i18n.detect(), "ru")
            os.environ["LC_ALL"] = "C.UTF-8"
            self.assertEqual(i18n.detect(), "ru")          # C is skipped, LANG decides
            os.environ["LANGUAGE"] = "en_US:en"
            self.assertEqual(i18n.detect(), "en")
            os.environ["LLMSCRUB_LANG"] = "ru"
            self.assertEqual(i18n.detect(), "ru")
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_messages_switch_language(self):
        s = Session(CFG)
        f = s.leak_check("ip 10.1.2.3")[0]
        i18n.set_lang("en")
        self.assertIn("not masked", f.message)
        i18n.set_lang("ru")
        self.assertIn("не обезличен", f.message)

    def test_example_configs_parse(self):
        import tomllib
        for lang in i18n.LANGS:
            data = tomllib.loads(example_config(lang))
            self.assertIn("suffixes", data["domains"])


if __name__ == "__main__":
    unittest.main()
