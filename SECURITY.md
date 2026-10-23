# Security policy

llmscrub is a best-effort, rule-based tool. It reduces the chance of leaking
infrastructure details to an AI service, but it is not a guarantee: always
review the pseudonymised text before you send it.

## Never share real data

Do not paste real configs, logs, host names, IP addresses, user names or
secrets into issues, pull requests or discussions — not even partially
redacted. Rebuild every example with fictional values (`acme.lan`, `db01`,
`ivanov`, `10.20.30.15`, the documentation ranges `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`).

## A value was not masked

That is a detection gap, not a vulnerability. Open an issue with the
"Missed or wrong replacement" template and a fictional, minimal example.

## Vulnerabilities in llmscrub itself

For example: the leak check can be bypassed in a systematic way, pseudonyms
can be reversed without the session key, or a crafted config or input makes
llmscrub run code or write files. Please report these privately through
GitHub: **Security → Report a vulnerability** in this repository. Do not open
a public issue.

## Supported versions

Only the latest release receives fixes.

---

**По-русски:** не публикуйте реальные данные в issues — только вымышленные
примеры. Пропущенное значение — это issue по шаблону. Уязвимость самого
llmscrub — приватно через Security → Report a vulnerability.
