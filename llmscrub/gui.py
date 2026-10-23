"""Two-pane Tkinter window. No network, no files: the session lives in memory."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from .config import load_config
from .engine import Finding, Result, Session, Span
from .i18n import t

COLORS = {
    "masked": "#c8f0d0",     # replaced by a pseudonym
    "restored": "#c8f0d0",   # restored from the session
    "secret": "#ffc9c9",     # irreversible placeholder
    "derived": "#cfe3ff",    # computed from a known prefix
    "unknown": "#ffeaa0",    # not from this session, left as is
    "ambiguous": "#ffcf99",
    "leak": "#ff7b7b",       # original value found in text for the AI
    "focus": "#b9b9ff",
}
LEGEND = ["masked", "secret", "derived", "unknown", "ambiguous", "leak"]
MAX_TAGS = 30000
LEVEL_ICON = {"error": "✖", "warn": "▲", "info": "●"}


class App:
    def __init__(self, root: tk.Tk, config_path: str):
        self.root = root
        self.config_path = config_path
        self.cfg = load_config(config_path)
        self.session = Session(self.cfg)
        self.busy = False
        self.jobs: queue.Queue = queue.Queue()
        self.copied = False
        self.finding_targets: list[tuple[tk.Text, int, int]] = []

        root.title(t("gui.title"))
        root.geometry("1400x860")
        mono = tkfont.nametofont("TkFixedFont")
        mono.configure(size=10)

        self._build_toolbar()
        self._build_panes(mono)
        self._build_bottom()
        self._bind_keys()
        self._show_findings(self._cfg_findings())
        self._update_status()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(100, self._poll)

    # ------------------------------------------------------------ layout
    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(6, 6, 6, 2))
        bar.pack(fill="x")
        self.btn_mask = ttk.Button(bar, text=t("gui.mask"), command=self.do_mask)
        self.btn_unmask = ttk.Button(bar, text=t("gui.unmask"), command=self.do_unmask)
        self.btn_mask.pack(side="left")
        self.btn_unmask.pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(bar, text=t("gui.copy_ai"), command=self.copy_right).pack(side="left")
        ttk.Button(bar, text=t("gui.copy_restored"), command=self.copy_left).pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(bar, text=t("gui.mapping"), command=self.show_mapping).pack(side="left")
        ttk.Button(bar, text=t("gui.clear"), command=self.clear_panes).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text=t("gui.new_session"), command=self.new_session).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text=t("gui.reload"), command=self.reload_config).pack(side="left", padx=(6, 0))

        legend = ttk.Frame(self.root, padding=(8, 0, 8, 4))
        legend.pack(fill="x")
        for key in LEGEND:
            tk.Label(legend, text=f"  {t('gui.legend_' + key)}  ", bg=COLORS[key], fg="#000").pack(
                side="left", padx=(0, 6))
        ttk.Label(legend, text=t("gui.keys")).pack(side="right")

    def _make_text(self, parent, mono) -> tk.Text:
        frame = ttk.Frame(parent)
        txt = tk.Text(frame, wrap="none", undo=True, font=mono, bg="#ffffff", fg="#111111",
                      insertbackground="#111111", selectbackground="#9cc3ff", selectforeground="#000000")
        ys = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        txt.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        for key, color in COLORS.items():
            txt.tag_configure(key, background=color)
        txt.tag_configure("leak", background=COLORS["leak"], foreground="#000")
        txt.tag_raise("leak")
        txt.tag_raise("focus")
        txt.tag_raise("sel")
        frame.pack(fill="both", expand=True)
        return txt

    def _build_panes(self, mono):
        pw = ttk.Panedwindow(self.root, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=6)
        left = ttk.Frame(pw)
        right = ttk.Frame(pw)
        pw.add(left, weight=1)
        pw.add(right, weight=1)
        ttk.Label(left, text=t("gui.left_label"), padding=(2, 2)).pack(anchor="w")
        ttk.Label(right, text=t("gui.right_label"), padding=(2, 2)).pack(anchor="w")
        self.left = self._make_text(left, mono)
        self.right = self._make_text(right, mono)

    def _build_bottom(self):
        bottom = ttk.Frame(self.root, padding=(6, 4, 6, 0))
        bottom.pack(fill="x")
        ttk.Label(bottom, text=t("gui.findings")).pack(anchor="w")
        lf = ttk.Frame(bottom)
        lf.pack(fill="x")
        self.findings = tk.Listbox(lf, height=7, activestyle="none")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.findings.yview)
        self.findings.configure(yscrollcommand=sb.set)
        self.findings.pack(side="left", fill="x", expand=True)
        sb.pack(side="left", fill="y")
        self.findings.bind("<Double-Button-1>", self._goto_finding)
        self.findings.bind("<Return>", self._goto_finding)
        self.status = ttk.Label(self.root, padding=(8, 3), anchor="w")
        self.status.pack(fill="x")

    def _bind_keys(self):
        for w in (self.left, self.right):
            w.bind("<Control-Return>", lambda e: (self.do_mask(), "break")[1])
            w.bind("<Control-Shift-Return>", lambda e: (self.do_unmask(), "break")[1])
            w.bind("<Control-a>", self._select_all)
            w.bind("<Control-A>", self._select_all)
            w.bind("<<Paste>>", self._paste)
        self.root.bind("<Control-Return>", lambda e: self.do_mask())
        self.root.bind("<Control-Shift-Return>", lambda e: self.do_unmask())

    @staticmethod
    def _select_all(event):
        event.widget.tag_add("sel", "1.0", "end-1c")
        event.widget.mark_set("insert", "end-1c")
        return "break"

    @staticmethod
    def _paste(event):
        w = event.widget
        try:
            data = w.clipboard_get()
        except tk.TclError:
            return "break"
        try:
            w.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        w.insert("insert", data)
        w.see("insert")
        return "break"

    # ------------------------------------------------------------ helpers
    def _cfg_findings(self) -> list[Finding]:
        return [Finding("in", 0, 0, "warn", "raw", {"text": w}) for w in self.cfg.warnings]

    @staticmethod
    def _get(w: tk.Text) -> str:
        return w.get("1.0", "end-1c")

    @staticmethod
    def _idx(pos: int) -> str:
        return f"1.0+{pos}c"

    def _set(self, w: tk.Text, text: str):
        w.delete("1.0", "end")
        w.insert("1.0", text)
        w.edit_reset()

    def _clear_tags(self, w: tk.Text):
        for key in COLORS:
            w.tag_remove(key, "1.0", "end")

    def _paint(self, w: tk.Text, spans: list[Span]):
        self._clear_tags(w)
        for sp in spans[:MAX_TAGS]:
            w.tag_add(sp.kind, self._idx(sp.start), self._idx(sp.end))

    def _show_findings(self, findings: list[Finding], left_is_in: bool = True):
        self.findings.delete(0, "end")
        self.finding_targets = []
        for f in findings:
            if left_is_in:
                w = self.left if f.pane == "in" else self.right
            else:
                w = self.right if f.pane == "in" else self.left
            line = ""
            if f.end > f.start:
                num = w.index(self._idx(f.start)).split(".")[0]
                side = t("gui.left") if w is self.left else t("gui.right")
                line = t("gui.where", side=side, line=num)
            self.findings.insert("end", f"{LEVEL_ICON.get(f.level, '•')} {line}{f.message}")
            color = {"error": "#b00000", "warn": "#8a5a00"}.get(f.level)
            if color:
                self.findings.itemconfigure("end", foreground=color)
            self.finding_targets.append((w, f.start, f.end))

    def _goto_finding(self, _event=None):
        sel = self.findings.curselection()
        if not sel:
            return
        w, s, e = self.finding_targets[sel[0]]
        if e <= s:
            return
        for pane in (self.left, self.right):
            pane.tag_remove("focus", "1.0", "end")
        w.tag_add("focus", self._idx(s), self._idx(e))
        w.see(self._idx(s))
        w.mark_set("insert", self._idx(s))
        w.focus_set()

    def _update_status(self, extra: str = ""):
        st = self.session.stats()
        parts = [f"{t('stat.' + k)}: {v}" for k, v in st.items() if v]
        sess = " · ".join(parts) if parts else t("gui.empty")
        path = self.cfg.path or ""
        home = os.path.expanduser("~")
        if home not in ("", "/") and path.startswith(home + os.sep):
            path = "~" + path[len(home):]
        cfg = path if not self.cfg.warnings else t("gui.cfg_warn", path=path)
        msg = t("gui.status", sess=sess, cfg=cfg)
        if extra:
            msg = f"{extra}   |   {msg}"
        self.status.configure(text=msg)

    def _set_busy(self, busy: bool, what: str = ""):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.btn_mask.configure(state=state)
        self.btn_unmask.configure(state=state)
        self.root.configure(cursor="watch" if busy else "")
        if busy:
            self._update_status(what)

    # ------------------------------------------------------------ worker
    def _run(self, label: str, fn, done):
        if self.busy:
            return
        self._set_busy(True, label)

        def work():
            try:
                self.jobs.put((done, fn(), None))
            except Exception as exc:  # pragma: no cover - shown to the user
                self.jobs.put((done, None, exc))

        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                done, result, exc = self.jobs.get_nowait()
                self._set_busy(False)
                if exc is not None:
                    messagebox.showerror(t("gui.error"), f"{type(exc).__name__}: {exc}")
                    self._update_status()
                else:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    # ------------------------------------------------------------ actions
    def do_mask(self):
        text = self._get(self.left)
        if not text.strip():
            return

        def done(res: Result):
            self._set(self.right, res.text)
            self._paint(self.right, res.out_spans)
            self._paint(self.left, res.in_spans)
            for f in res.findings:
                if f.level == "error" and f.pane == "out":
                    self.right.tag_add("leak", self._idx(f.start), self._idx(f.end))
            self._show_findings(res.findings, left_is_in=True)
            n = len(res.out_spans)
            errs = sum(1 for f in res.findings if f.level == "error")
            msg = t("gui.masked", n=n) + (t("gui.leaks", n=errs) if errs else "")
            self._update_status(msg)

        self._run(t("gui.masking"), lambda: self.session.mask(text), done)

    def do_unmask(self):
        text = self._get(self.right)
        if not text.strip():
            return

        def done(res: Result):
            self._set(self.left, res.text)
            self._paint(self.left, res.out_spans)
            self._paint(self.right, res.in_spans)
            self._show_findings(res.findings, left_is_in=False)
            counts: dict[str, int] = {}
            for sp in res.out_spans:
                counts[sp.kind] = counts.get(sp.kind, 0) + 1
            items = ", ".join(f"{t('gui.k_' + k)} {v}" for k, v in counts.items())
            self._update_status(t("gui.restore_summary", items=items))

        self._run(t("gui.restoring"), lambda: self.session.unmask(text), done)

    def copy_right(self):
        text = self._get(self.right)
        if not text.strip():
            return
        found = self.session.leak_check(text)
        self.right.tag_remove("leak", "1.0", "end")
        if found:
            for f in found:
                self.right.tag_add("leak", self._idx(f.start), self._idx(f.end))
            self._show_findings(found, left_is_in=True)
            if not messagebox.askyesno(t("gui.leak_title"), t("gui.leak_text", n=len(found)),
                                       default="no", icon="warning"):
                self._update_status(t("gui.copy_cancelled"))
                return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.copied = True
        self._update_status(t("gui.copied_ai_warn") if found else t("gui.copied_ai"))

    def copy_left(self):
        text = self._get(self.left)
        if not text.strip():
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.copied = True
        self._update_status(t("gui.copied_restored"))

    def clear_panes(self):
        for w in (self.left, self.right):
            self._set(w, "")
            self._clear_tags(w)
        self.findings.delete(0, "end")
        self._update_status()

    def new_session(self):
        if not messagebox.askyesno(t("gui.new_title"), t("gui.new_text"), default="no"):
            return
        self.session = Session(self.cfg)
        self.clear_panes()
        self._update_status(t("gui.new_done"))

    def reload_config(self):
        self.cfg = load_config(self.config_path)
        self.session.apply_config(self.cfg)
        self._show_findings(self._cfg_findings())
        self._update_status(t("gui.reloaded"))

    def show_mapping(self):
        top = tk.Toplevel(self.root)
        top.title(t("gui.map_title"))
        top.geometry("760x520")
        cols = ("cat", "orig", "pseudo")
        tree = ttk.Treeview(top, columns=cols, show="headings")
        titles = (t("gui.col_type"), t("gui.col_orig"), t("gui.col_pseudo"))
        for c, title, wdt in zip(cols, titles, (120, 330, 280)):
            tree.heading(c, text=title)
            tree.column(c, width=wdt, anchor="w")
        sb = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        for row in self.session.mapping_rows():
            tree.insert("", "end", values=row)

    def _on_close(self):
        if self.copied:
            try:
                self.root.clipboard_clear()
            except tk.TclError:
                pass
        self.root.destroy()


def run(config_path: str) -> int:
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("clam")
    except tk.TclError:
        pass
    App(root, config_path)
    root.mainloop()
    return 0
