# Changelog

## 0.1.0 — 2026-10-23

First public release.

- Two-pane Tkinter window: pseudonymise on the left → right, restore the AI answer right → left, with highlighting of what was replaced, restored, derived, unknown or left for manual input.
- Reversible, consistent pseudonyms within a session: IPv4 (class- and prefix-preserving, last octet kept), PTR zones, FQDNs under configured suffixes, Kerberos realms, LDAP DNs, short host names, user names, person names, configured company strings.
- Irreversible placeholders for passwords, tokens, password hashes, private keys, certificates and card numbers (Luhn-checked).
- audit.log hex fields are decoded, pseudonymised and re-encoded.
- Leak check before copying: original values and unmasked IPs block the copy until confirmed.
- CLI filters `mask`, `unmask`, `check`, `session`, `init-config`.
- English and Russian interface, selected from the system locale, `LLMSCRUB_LANG` or `--lang`.
- No network access, no dependencies beyond the Python standard library and Tk.
