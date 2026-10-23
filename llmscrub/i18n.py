"""Tiny message catalogue: English (default) and Russian.

Language selection, first match wins:
  1. set_lang() — the --lang option;
  2. LLMSCRUB_LANG=en|ru;
  3. the system locale: LANGUAGE, LC_ALL, LC_MESSAGES, LANG (gettext order);
     a value starting with "ru" selects Russian, anything else English.
"""

from __future__ import annotations

import os

LANGS = ("en", "ru")
_lang: str | None = None


def detect() -> str:
    v = os.environ.get("LLMSCRUB_LANG", "").strip().lower()
    if v[:2] in LANGS:
        return v[:2]
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "").strip()
        if not val:
            continue
        first = val.split(":")[0].lower()
        if first in ("c", "posix") or first.startswith(("c.", "posix.")):
            continue
        return "ru" if first.startswith("ru") else "en"
    return "en"


def set_lang(lang: str | None) -> None:
    global _lang
    _lang = lang if lang in LANGS else None


def get_lang() -> str:
    return _lang or detect()


def t(key: str, **kw) -> str:
    lang = get_lang()
    msg = MESSAGES[lang].get(key) or MESSAGES["en"].get(key) or key
    return msg.format(**kw) if kw else msg


MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        # ---- findings
        "f.raw": "{text}",
        "f.input_collides": "The source text contains “{tok}”, which equals a pseudonym of this "
                            "session — restoring it may be ambiguous",
        "f.leak_ip": "Original IP in the text: {ip}",
        "f.unmasked_ip": "IP is not masked (not from this session): {ip}",
        "f.leak_string": "Original domain/string in the text: {v}",
        "f.leak_name": "Original name (host/user) in the text: {v}",
        "f.leak_secret": "Original secret value in the text",
        "f.secret_placeholder": "{tok}: secrets are never restored — insert the value manually",
        "f.ip_unknown": "{tok}: IP is not from this session — left as is, please check",
        "f.ip_derived": "{tok} → {rep}: address derived from a known session prefix, please check",
        "f.ip_ambiguous": "{tok}: ambiguous, candidates: {cands}",
        "f.domain_unknown": "{tok}: domain is not from this session — left as is",
        "f.labels_unknown": "{tok}: some labels are not from this session — left as is",
        "f.pseudo_unknown": "{tok}: pseudonym not found in this session — left as is",
        # ---- statistics / mapping table
        "stat.ip": "IP",
        "stat.domains": "domains",
        "stat.hosts": "hosts",
        "stat.zones": "zones",
        "stat.users": "users",
        "stat.names": "names",
        "stat.strings": "strings",
        "stat.secrets": "secrets",
        "cat.ip": "IP",
        "cat.domain": "domain",
        "cat.string": "string",
        "cat.host": "host",
        "cat.zone": "zone",
        "cat.user": "user",
        "cat.name": "person name",
        "cat.secret": "secret",
        "cat.secret_value": "•••• (not stored in clear text)",
        # ---- config
        "cfg.not_found": "Config not found ({path}). Only automatic rules apply: without a config "
                         "domains and short host names are barely detected.",
        "cfg.perms": "Config is readable by group/others: run chmod 600 {path}",
        "cfg.bad_list": "{where}.{key}: a list of strings is expected, value ignored",
        "cfg.bad_ip": "ips.keep: not an IPv4 address/CIDR: {item}",
        "cfg.parse_error": "Config {path} could not be read ({err}); it is ignored",
        # ---- CLI
        "cli.description": (
            "llmscrub — local, reversible pseudonymisation of configs and logs before sending them to an AI.\n\n"
            "  llmscrub                 two-pane window (default)\n"
            "  llmscrub mask   < in     pseudonymise stdin -> stdout\n"
            "  llmscrub unmask < in     restore an AI answer stdin -> stdout\n"
            "  llmscrub check  < in     check a text for original values\n"
            "  llmscrub init-config     create an example config (mode 0600)\n"
            "  llmscrub session show|clear\n\n"
            "The CLI keeps its session mapping in $XDG_RUNTIME_DIR/llmscrub/session.json\n"
            "(tmpfs, removed at logout, mode 0600). The window keeps it in memory only."
        ),
        "cli.h_action": "for the session command",
        "cli.h_config": "config path (default {path})",
        "cli.h_session": "session mapping file for the CLI",
        "cli.h_force": "mask: print the result even if a leak was found",
        "cli.h_lang": "interface language (default: from LLMSCRUB_LANG or the system locale)",
        "cli.no_tk": "Tkinter is not available ({err}). Install it: sudo apt install python3-tk",
        "cli.exists": "Already exists: {path}",
        "cli.created": "Created {path} (0600). Add your DNS suffixes and company strings.",
        "cli.no_runtime": "XDG_RUNTIME_DIR is not set: pass --session PATH (preferably on tmpfs)",
        "cli.session_cleared": "Session cleared",
        "cli.blocked": "Original values found in the result — output blocked (use --force to print it)",
        "cli.report": "[{level}] {where}, line {line}: {msg}",
        "cli.in": "input",
        "cli.out": "output",
        # ---- GUI
        "gui.title": "llmscrub — pseudonymise for AI (local)",
        "gui.mask": "Pseudonymise  →",
        "gui.unmask": "←  Restore",
        "gui.copy_ai": "Copy for AI",
        "gui.copy_restored": "Copy restored",
        "gui.mapping": "Mapping",
        "gui.clear": "Clear panes",
        "gui.new_session": "New session",
        "gui.reload": "Reload config",
        "gui.legend_masked": "replaced / restored",
        "gui.legend_secret": "secret (manual)",
        "gui.legend_derived": "derived from prefix",
        "gui.legend_unknown": "not from session",
        "gui.legend_ambiguous": "ambiguous",
        "gui.legend_leak": "leak",
        "gui.keys": "Ctrl+Enter — pseudonymise,  Ctrl+Shift+Enter — restore",
        "gui.left_label": "LOCAL: original config/log  •  the restored AI answer appears here",
        "gui.right_label": "FOR AI: pseudonymised text  •  paste the AI answer here",
        "gui.findings": "Warnings (double-click to jump):",
        "gui.where": "[{side}, line {line}] ",
        "gui.left": "left",
        "gui.right": "right",
        "gui.empty": "empty",
        "gui.cfg_warn": "{path} (has warnings)",
        "gui.status": "Session (memory only): {sess}   |   Config: {cfg}",
        "gui.error": "Error",
        "gui.masked": "Pseudonymised: {n} replacements",
        "gui.leaks": ", LEAKS: {n}",
        "gui.masking": "Pseudonymising…",
        "gui.restoring": "Restoring…",
        "gui.restore_summary": "Restore: {items}",
        "gui.k_restored": "restored",
        "gui.k_derived": "derived",
        "gui.k_unknown": "not from session",
        "gui.k_ambiguous": "ambiguous",
        "gui.k_secret": "secrets to insert manually",
        "gui.leak_title": "Original values found",
        "gui.leak_text": "The text for the AI contains {n} match(es) with original data.\n"
                         "They are highlighted in red. Fix the text on the right or add the value "
                         "to the config exceptions.\n\nCopy anyway?",
        "gui.copy_cancelled": "Copy cancelled",
        "gui.copied_ai": "Copied for AI, no leaks found",
        "gui.copied_ai_warn": "Copied for AI (with warnings)",
        "gui.copied_restored": "Restored text copied",
        "gui.new_title": "New session",
        "gui.new_text": "The current mapping will be deleted.\n"
                        "AI answers to texts already sent can no longer be restored.\n\nContinue?",
        "gui.new_done": "New session",
        "gui.reloaded": "Config reloaded",
        "gui.map_title": "Mapping of this session (local)",
        "gui.col_type": "Type",
        "gui.col_orig": "Original",
        "gui.col_pseudo": "Pseudonym",
    },
    "ru": {
        "f.raw": "{text}",
        "f.input_collides": "В исходном тексте есть «{tok}», совпадающий с псевдонимом сессии — "
                            "обратная замена для него может быть неоднозначной",
        "f.leak_ip": "Исходный IP в тексте: {ip}",
        "f.unmasked_ip": "IP не обезличен (не из этой сессии): {ip}",
        "f.leak_string": "Исходный домен/строка в тексте: {v}",
        "f.leak_name": "Исходное имя (хост/пользователь) в тексте: {v}",
        "f.leak_secret": "Исходное значение секрета в тексте",
        "f.secret_placeholder": "{tok}: секрет не восстанавливается — подставьте значение вручную",
        "f.ip_unknown": "{tok}: IP не из этой сессии — оставлен как есть, проверьте",
        "f.ip_derived": "{tok} → {rep}: адрес вычислен по префиксу сессии, проверьте",
        "f.ip_ambiguous": "{tok}: неоднозначно, варианты: {cands}",
        "f.domain_unknown": "{tok}: домен не из этой сессии — оставлен как есть",
        "f.labels_unknown": "{tok}: часть меток не из сессии — оставлены как есть",
        "f.pseudo_unknown": "{tok}: псевдоним не найден в сессии — оставлен как есть",
        "stat.ip": "IP",
        "stat.domains": "домены",
        "stat.hosts": "хосты",
        "stat.zones": "зоны",
        "stat.users": "пользователи",
        "stat.names": "имена",
        "stat.strings": "строки",
        "stat.secrets": "секреты",
        "cat.ip": "IP",
        "cat.domain": "домен",
        "cat.string": "строка",
        "cat.host": "хост",
        "cat.zone": "зона",
        "cat.user": "пользователь",
        "cat.name": "имя человека",
        "cat.secret": "секрет",
        "cat.secret_value": "•••• (не хранится в открытом виде)",
        "cfg.not_found": "Конфиг не найден ({path}). Работают только автоматические правила: "
                         "домены и короткие имена хостов без конфига почти не распознаются.",
        "cfg.perms": "Конфиг доступен группе/всем: выполните chmod 600 {path}",
        "cfg.bad_list": "{where}.{key}: ожидается список строк, значение пропущено",
        "cfg.bad_ip": "ips.keep: не IPv4-адрес/CIDR: {item}",
        "cfg.parse_error": "Не удалось прочитать конфиг {path} ({err}); он не используется",
        "cli.description": (
            "llmscrub — локальное обратимое обезличивание конфигов и логов перед отправкой в ИИ.\n\n"
            "  llmscrub                 окно с двумя панелями (по умолчанию)\n"
            "  llmscrub mask   < in     обезличить stdin -> stdout\n"
            "  llmscrub unmask < in     восстановить ответ ИИ stdin -> stdout\n"
            "  llmscrub check  < in     проверить текст на исходные значения\n"
            "  llmscrub init-config     создать пример конфига (права 0600)\n"
            "  llmscrub session show|clear\n\n"
            "Для CLI словарь сессии хранится в $XDG_RUNTIME_DIR/llmscrub/session.json\n"
            "(tmpfs, исчезает при выходе из системы, права 0600). Окно хранит словарь только в памяти."
        ),
        "cli.h_action": "для команды session",
        "cli.h_config": "путь к конфигу (по умолчанию {path})",
        "cli.h_session": "файл словаря сессии для CLI",
        "cli.h_force": "mask: выводить результат даже при найденной утечке",
        "cli.h_lang": "язык интерфейса (по умолчанию из LLMSCRUB_LANG или локали системы)",
        "cli.no_tk": "Нет Tkinter ({err}). Установите: sudo apt install python3-tk",
        "cli.exists": "Уже существует: {path}",
        "cli.created": "Создан {path} (0600). Впишите свои DNS-суффиксы и строки компании.",
        "cli.no_runtime": "Нет XDG_RUNTIME_DIR: укажите --session ПУТЬ (лучше на tmpfs)",
        "cli.session_cleared": "Сессия очищена",
        "cli.blocked": "Найдены исходные значения в результате — вывод заблокирован (--force чтобы вывести)",
        "cli.report": "[{level}] {where}, строка {line}: {msg}",
        "cli.in": "вход",
        "cli.out": "выход",
        "gui.title": "llmscrub — обезличивание для ИИ (локально)",
        "gui.mask": "Обезличить  →",
        "gui.unmask": "←  Восстановить",
        "gui.copy_ai": "Копировать для ИИ",
        "gui.copy_restored": "Копировать восстановленное",
        "gui.mapping": "Соответствия",
        "gui.clear": "Очистить окна",
        "gui.new_session": "Новая сессия",
        "gui.reload": "Перечитать конфиг",
        "gui.legend_masked": "заменено / восстановлено",
        "gui.legend_secret": "секрет (вручную)",
        "gui.legend_derived": "вычислено по префиксу",
        "gui.legend_unknown": "не из сессии",
        "gui.legend_ambiguous": "неоднозначно",
        "gui.legend_leak": "утечка",
        "gui.keys": "Ctrl+Enter — обезличить,  Ctrl+Shift+Enter — восстановить",
        "gui.left_label": "ЛОКАЛЬНО: исходный конфиг/лог  •  сюда же — восстановленный ответ ИИ",
        "gui.right_label": "ДЛЯ ИИ: обезличенный текст  •  сюда вставьте ответ ИИ",
        "gui.findings": "Предупреждения (двойной щелчок — перейти):",
        "gui.where": "[{side}, стр. {line}] ",
        "gui.left": "слева",
        "gui.right": "справа",
        "gui.empty": "пусто",
        "gui.cfg_warn": "{path} (есть предупреждения)",
        "gui.status": "Сессия (только в памяти): {sess}   |   Конфиг: {cfg}",
        "gui.error": "Ошибка",
        "gui.masked": "Обезличено: {n} замен",
        "gui.leaks": ", УТЕЧКИ: {n}",
        "gui.masking": "Обезличиваю…",
        "gui.restoring": "Восстанавливаю…",
        "gui.restore_summary": "Восстановление: {items}",
        "gui.k_restored": "восстановлено",
        "gui.k_derived": "вычислено",
        "gui.k_unknown": "не из сессии",
        "gui.k_ambiguous": "неоднозначно",
        "gui.k_secret": "секретов вручную",
        "gui.leak_title": "Найдены исходные значения",
        "gui.leak_text": "В тексте для ИИ найдено совпадений с исходными данными: {n}.\n"
                         "Они подсвечены красным. Исправьте текст справа или добавьте значение "
                         "в исключения конфига.\n\nВсё равно скопировать?",
        "gui.copy_cancelled": "Копирование отменено",
        "gui.copied_ai": "Скопировано для ИИ, утечек не найдено",
        "gui.copied_ai_warn": "Скопировано для ИИ (с предупреждениями)",
        "gui.copied_restored": "Восстановленный текст скопирован",
        "gui.new_title": "Новая сессия",
        "gui.new_text": "Текущий словарь соответствий будет удалён.\n"
                        "Ответы ИИ на уже отправленные тексты больше нельзя будет восстановить.\n\nПродолжить?",
        "gui.new_done": "Новая сессия",
        "gui.reloaded": "Конфиг перечитан",
        "gui.map_title": "Соответствия этой сессии (локально)",
        "gui.col_type": "Тип",
        "gui.col_orig": "Исходное",
        "gui.col_pseudo": "Псевдоним",
    },
}
