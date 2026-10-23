"""IPv4 pseudonymisation.

Properties:
  * keyed (HMAC-SHA256 with a random per-session key), reversible;
  * class-preserving: RFC1918 / CGNAT blocks map inside the same block,
    public addresses map to public addresses, special ranges stay as is;
  * prefix-preserving at bit level for the first 24 bits: two addresses that
    share an N-bit prefix (N <= 24) keep sharing an N-bit prefix, so subnets,
    CIDR containment and "same /24" relations survive;
  * the last octet is kept, so .0 / .1 / .255 keep their meaning.

The permutation is the classic Crypto-PAn construction: bit i of the output is
bit i of the input XOR PRF(key, first i input bits).  It is a bijection and
can be inverted bit by bit.  When a block contains ranges that must stay
untouched (user "keep" ranges) or for public space (which must avoid private
and special ranges) we use cycle-walking, which keeps the mapping a
bijection on the allowed set.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re

IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Not preceded by a word char or dot, not followed by a word char or ".digit"
# (that excludes OIDs like 1.3.6.1.4.1 and 5-part version strings).
IPV4_RE_TEXT = (
    rf"(?<![\w.]){IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}"
    rf"(?:/(?:3[0-2]|[12]?\d)(?!\d))?(?![\w])(?!\.\d)"
)
IPV4_RE = re.compile(IPV4_RE_TEXT)
MASK_AFTER_RE = re.compile(
    rf"(?:[ \t]*/[ \t]*|[ \t]+(?:(?:net)?mask[ \t]+)?)"
    rf"({IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET})(?![\w])(?!\.\d)",
    re.IGNORECASE,
)


def ip2int(s: str) -> int:
    a, b, c, d = (int(x) for x in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int2ip(n: int) -> str:
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def is_netmask(n: int) -> bool:
    if n == 0:
        return False
    inv = (~n) & 0xFFFFFFFF
    return (inv & (inv + 1)) == 0


def mask_len(n: int) -> int:
    return 32 - ((~n) & 0xFFFFFFFF).bit_length()


def host_bits(L: int) -> int:
    return (1 << (32 - L)) - 1 if L < 32 else 0


def _net(text: str) -> tuple[int, int]:
    n = ipaddress.ip_network(text, strict=False)
    return int(n.network_address), n.prefixlen


# Identity ranges.  All of them are /24 or wider, so classification can be
# done on the first 24 bits.
BUILTIN_KEEP = [
    _net(x)
    for x in (
        "0.0.0.0/8",        # "this network", wildcard masks
        "127.0.0.0/8",      # loopback
        "169.254.0.0/16",   # link-local
        "192.0.0.0/24",     # IETF protocol assignments
        "192.0.2.0/24",     # TEST-NET-1
        "192.88.99.0/24",   # 6to4 relay
        "198.18.0.0/15",    # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",   # TEST-NET-3
        "224.0.0.0/4",      # multicast
        "240.0.0.0/4",      # reserved, includes broadcast and most masks
        "128.0.0.0/24",     # so that the 128.0.0.0 netmask is never produced
    )
]

PRIVATE_BLOCKS = [
    ("p10", *_net("10.0.0.0/8")),
    ("p172", *_net("172.16.0.0/12")),
    ("p192", *_net("192.168.0.0/16")),
    ("cgn", *_net("100.64.0.0/10")),
]


def _in(addr: int, net: int, L: int) -> bool:
    if L == 0:
        return True
    return (addr >> (32 - L)) == (net >> (32 - L))


class IPMapper:
    def __init__(self, key: bytes, keep: list[str] | None = None):
        self.key = key
        self.keep_exact: set[int] = set()
        self.keep_nets: list[tuple[int, int]] = []
        for item in keep or []:
            item = item.strip()
            if not item:
                continue
            if "/" in item:
                self.keep_nets.append(_net(item))
            else:
                self.keep_exact.add(ip2int(item))
        # User keep ranges that are /24 or wider take part in classification,
        # so pseudonyms never land inside them.
        self._class_keep = BUILTIN_KEEP + [(n, L) for n, L in self.keep_nets if L <= 24]
        self._flip_cache: dict[tuple[str, int, int], int] = {}
        self._fwd24: dict[int, int] = {}
        self._rev24: dict[int, int] = {}

    # ---------- primitives ----------
    def _flip(self, dom: str, i: int, prefix: int) -> int:
        k = (dom, i, prefix)
        v = self._flip_cache.get(k)
        if v is None:
            d = hmac.new(self.key, f"{dom}|{i}|{prefix}".encode(), hashlib.sha256).digest()
            v = d[0] & 1
            self._flip_cache[k] = v
        return v

    def _perm(self, dom: str, value: int, width: int) -> int:
        out = 0
        for i in range(width):
            prefix = value >> (width - i)
            bit = (value >> (width - 1 - i)) & 1
            out = (out << 1) | (bit ^ self._flip(dom, i, prefix))
        return out

    def _unperm(self, dom: str, value: int, width: int) -> int:
        val = 0
        for i in range(width):
            obit = (value >> (width - 1 - i)) & 1
            val = (val << 1) | (obit ^ self._flip(dom, i, val))
        return val

    # ---------- classification ----------
    def classify24(self, p24: int):
        a = p24 << 8
        for net, L in self._class_keep:
            if _in(a, net, L):
                return ("keep", None)
        for name, net, L in PRIVATE_BLOCKS:
            if _in(a, net, L):
                return ("private", (name, net, L))
        return ("public", None)

    def is_kept(self, a: int) -> bool:
        if a in self.keep_exact or is_netmask(a):
            return True
        for net, L in self.keep_nets:
            if _in(a, net, L):
                return True
        return self.classify24(a >> 8)[0] == "keep"

    # ---------- /24 prefix mapping ----------
    def map24(self, p24: int) -> int:
        r = self._fwd24.get(p24)
        if r is not None:
            return r
        cls = self.classify24(p24)
        if cls[0] == "keep":
            r = p24
        elif cls[0] == "private":
            name, net, L = cls[1]
            w = 24 - L
            fixed = (p24 >> w) << w
            y = p24 & ((1 << w) - 1)
            while True:
                y = self._perm(name, y, w)
                cand = fixed | y
                if self.classify24(cand) == cls:
                    r = cand
                    break
        else:
            y = p24
            while True:
                y = self._perm("pub", y, 24)
                if self.classify24(y)[0] == "public":
                    r = y
                    break
        self._fwd24[p24] = r
        self._rev24[r] = p24
        return r

    def unmap24(self, q24: int) -> int:
        r = self._rev24.get(q24)
        if r is not None:
            return r
        cls = self.classify24(q24)
        if cls[0] == "keep":
            r = q24
        elif cls[0] == "private":
            name, net, L = cls[1]
            w = 24 - L
            fixed = (q24 >> w) << w
            x = q24 & ((1 << w) - 1)
            while True:
                x = self._unperm(name, x, w)
                cand = fixed | x
                if self.classify24(cand) == cls:
                    r = cand
                    break
        else:
            x = q24
            while True:
                x = self._unperm("pub", x, 24)
                if self.classify24(x)[0] == "public":
                    r = x
                    break
        self._rev24[q24] = r
        self._fwd24[r] = q24
        return r

    # ---------- address / network mapping ----------
    def _block_len(self, a: int) -> int | None:
        cls = self.classify24(a >> 8)
        return cls[1][2] if cls[0] == "private" else None

    def map_host(self, a: int) -> int:
        return (self.map24(a >> 8) << 8) | (a & 0xFF)

    def unmap_host(self, q: int) -> int:
        return (self.unmap24(q >> 8) << 8) | (q & 0xFF)

    def map_net(self, a: int, L: int) -> int:
        bl = self._block_len(a)
        if bl is not None and L <= bl:
            return a
        return (self.map24(a >> 8) << 8) & ~host_bits(L) & 0xFFFFFFFF

    def unmap_net(self, q: int, L: int) -> int:
        bl = self._block_len(q)
        if bl is not None and L <= bl:
            return q
        return (self.unmap24(q >> 8) << 8) & ~host_bits(L) & 0xFFFFFFFF

    @staticmethod
    def shape(a: int, L: int | None) -> tuple[str, int | None]:
        """Decide whether a token is a host or a network, from its form only.

        Same rule is used in both directions, so it is symmetric:
          * explicit prefix (CIDR or netmask) shorter than /24 with zero host
            bits -> network;
          * no prefix and the last two (three) octets are zero -> /16 (/8);
          * everything else -> host (first 24 bits mapped, last octet kept).
        """
        if L is not None:
            if L < 24 and (a & host_bits(L)) == 0:
                return "net", L
            return "host", None
        if a & 0xFFFFFF == 0:
            return "net", 8
        if a & 0xFFFF == 0:
            return "net", 16
        return "host", None

    def forward(self, a: int, L: int | None = None) -> tuple[int, str, int | None]:
        if self.is_kept(a):
            return a, "keep", None
        kind, nl = self.shape(a, L)
        if kind == "net":
            return self.map_net(a, nl), "net", nl
        return self.map_host(a), "host", None

    def reverse(self, q: int, L: int | None = None) -> tuple[int, str, int | None]:
        if self.is_kept(q):
            return q, "keep", None
        kind, nl = self.shape(q, L)
        if kind == "net":
            return self.unmap_net(q, nl), "net", nl
        return self.unmap_host(q), "host", None
