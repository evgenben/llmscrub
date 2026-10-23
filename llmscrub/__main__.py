"""Command-line entry point: the window by default, plus mask / unmask / check filters."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .config import DEFAULT_PATH, example_config, load_config
from .engine import Session
from .i18n import LANGS, set_lang, t


def _default_session_path() -> str | None:
    rd = os.environ.get("XDG_RUNTIME_DIR")
    return os.path.join(rd, "llmscrub", "session.json") if rd else None


def _load_session(path: str, cfg) -> Session:
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return Session.from_dict(json.load(f), cfg)
    return Session(cfg)


def _save_session(path: str, s: Session) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(s.to_dict(), f)
    os.replace(tmp, path)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _report(findings, text_in: str, text_out: str) -> None:
    for f in findings:
        src = text_in if f.pane == "in" else text_out
        where = t("cli.in") if f.pane == "in" else t("cli.out")
        print(t("cli.report", level=f.level, where=where, line=_line_of(src, f.start), msg=f.message),
              file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="llmscrub", description=t("cli.description"),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="gui",
                    choices=["gui", "mask", "unmask", "check", "init-config", "session"])
    ap.add_argument("action", nargs="?", choices=["show", "clear"], help=t("cli.h_action"))
    ap.add_argument("--config", default=DEFAULT_PATH, help=t("cli.h_config", path=DEFAULT_PATH))
    ap.add_argument("--session", default=_default_session_path(), help=t("cli.h_session"))
    ap.add_argument("--force", action="store_true", help=t("cli.h_force"))
    ap.add_argument("--lang", choices=LANGS, help=t("cli.h_lang"))
    ap.add_argument("--version", action="version", version=f"llmscrub {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    # The language must be known before the help texts are built.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=LANGS)
    known, _ = pre.parse_known_args(argv)
    set_lang(known.lang)

    args = _parser().parse_args(argv)

    if args.command == "gui":
        try:
            from .gui import run
        except ImportError as exc:
            print(t("cli.no_tk", err=exc), file=sys.stderr)
            return 1
        return run(args.config)

    if args.command == "init-config":
        path = args.config
        if os.path.exists(path):
            print(t("cli.exists", path=path), file=sys.stderr)
            return 1
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(example_config())
        print(t("cli.created", path=path), file=sys.stderr)
        return 0

    cfg = load_config(args.config)
    for w in cfg.warnings:
        print(f"[warn] {w}", file=sys.stderr)

    if not args.session:
        print(t("cli.no_runtime"), file=sys.stderr)
        return 1

    if args.command == "session":
        if args.action == "clear":
            if os.path.exists(args.session):
                os.remove(args.session)
            print(t("cli.session_cleared"), file=sys.stderr)
            return 0
        s = _load_session(args.session, cfg)
        for cat, orig, pseudo in s.mapping_rows():
            print(f"{cat}\t{orig}\t{pseudo}")
        return 0

    s = _load_session(args.session, cfg)
    text = sys.stdin.read()

    if args.command == "mask":
        res = s.mask(text)
        _save_session(args.session, s)
        _report(res.findings, text, res.text)
        if any(f.level == "error" for f in res.findings) and not args.force:
            print(t("cli.blocked"), file=sys.stderr)
            return 2
        sys.stdout.write(res.text)
        return 0

    if args.command == "unmask":
        res = s.unmask(text)
        _report(res.findings, text, res.text)
        sys.stdout.write(res.text)
        return 0

    if args.command == "check":
        found = s.leak_check(text)
        _report(found, text, text)
        return 1 if found else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
