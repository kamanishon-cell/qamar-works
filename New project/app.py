from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import secrets
import socket
import sqlite3
import threading
import time
from datetime import date, datetime, timedelta
from html import escape
from http.cookies import SimpleCookie
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urlparse


APP_NAME = "UniTask"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "unitask.db"
HOST = os.environ.get("UNITASK_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("UNITASK_PORT", "8000")))
REMINDER_REPEAT_MINUTES = int(os.environ.get("UNITASK_REPEAT_MINUTES", "30"))
SESSION_DAYS = 14
PASSWORD_ITERATIONS = 120_000
SESSION_COOKIE = "unitask_session"


PRIORITY_LABELS = {
    "high": "Высокая",
    "normal": "Обычная",
    "low": "Низкая",
}

PRIORITY_BADGES = {
    "high": "priority-high",
    "normal": "priority-normal",
    "low": "priority-low",
}

RECURRENCE_LABELS = {
    "once": "Единожды",
    "daily": "Каждый день",
    "weekdays": "Будние дни",
    "custom": "Выбрать дни",
}

CATEGORY_LABELS = {
    "assignment": "Задание",
    "exam": "Экзамен",
    "project": "Проект",
    "personal": "Личное",
}

SOURCE_LABELS = {
    "manual": "Вручную",
    "university": "Университет",
}

WEEKDAY_LABELS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
MONTH_LABELS = [
    "",
    "Январь",
    "Февраль",
    "Март",
    "Апрель",
    "Май",
    "Июнь",
    "Июль",
    "Август",
    "Сентябрь",
    "Октябрь",
    "Ноябрь",
    "Декабрь",
]


def now_local() -> datetime:
    return datetime.now().replace(second=0, microsecond=0)


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'assignment',
                priority TEXT NOT NULL DEFAULT 'normal',
                due_at TEXT NOT NULL,
                remind_before_minutes INTEGER NOT NULL DEFAULT 0,
                recurrence TEXT NOT NULL DEFAULT 'once',
                recurrence_days TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'manual',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                last_completed_at TEXT
            )
            """
        )
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if "user_id" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN user_id INTEGER")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                answered_at TEXT,
                answer TEXT,
                reminder_count INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_user_status ON tasks(user_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_task ON notifications(task_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def normalize_username(username: str) -> str:
    return username.strip().lower()


def username_is_valid(username: str) -> bool:
    if not 3 <= len(username) <= 40:
        return False
    return all(char.isalnum() or char in "._-" for char in username)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return hmac.compare_digest(actual, expected)


def create_user(username: str, password: str) -> tuple[sqlite3.Row | None, str | None]:
    username = normalize_username(username)
    if not username_is_valid(username):
        return None, "Логин должен быть от 3 до 40 символов: буквы, цифры, точка, дефис или подчёркивание."
    if len(password) < 6:
        return None, "Пароль должен быть минимум 6 символов."

    created_at = now_local().isoformat(timespec="minutes")
    with db() as conn:
        existing_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        try:
            cursor = conn.execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (username, hash_password(password), created_at),
            )
        except sqlite3.IntegrityError:
            return None, "Такой логин уже занят."

        user_id = int(cursor.lastrowid)
        if existing_count == 0:
            conn.execute(
                "UPDATE tasks SET user_id = ? WHERE user_id IS NULL",
                (user_id,),
            )
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone(), None


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    username = normalize_username(username)
    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if user and verify_password(password, user["password_hash"]):
        return user
    return None


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    created_at = now_local()
    expires_at = created_at + timedelta(days=SESSION_DAYS)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                token,
                user_id,
                created_at.isoformat(timespec="minutes"),
                expires_at.isoformat(timespec="minutes"),
            ),
        )
    return token


def get_user_by_session(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None

    now_text = now_local().isoformat(timespec="minutes")
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_text,))
        return conn.execute(
            """
            SELECT users.*
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND sessions.expires_at >= ?
            """,
            (token, now_text),
        ).fetchone()


def delete_session(token: str | None) -> None:
    if not token:
        return
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def format_due(value: str) -> str:
    parsed = parse_dt(value)
    if not parsed:
        return escape(value)
    return parsed.strftime("%d.%m.%Y %H:%M")


def task_date(value: str) -> date | None:
    parsed = parse_dt(value)
    return parsed.date() if parsed else None


def first_value(form: dict[str, list[str]], key: str, default: str = "") -> str:
    values = form.get(key)
    if not values:
        return default
    return values[0].strip()


def next_due_for_recurrence(
    current_due: datetime,
    recurrence: str,
    recurrence_days: str,
    after: datetime | None = None,
) -> datetime | None:
    if recurrence == "once":
        return None

    after = after or now_local()
    selected_days: set[int] = set()
    if recurrence == "custom":
        for item in recurrence_days.split(","):
            if item.strip().isdigit():
                selected_days.add(int(item.strip()))
        if not selected_days:
            selected_days = set(range(7))

    candidate = current_due
    for _ in range(370):
        candidate = candidate + timedelta(days=1)
        if recurrence == "daily":
            matches = True
        elif recurrence == "weekdays":
            matches = candidate.weekday() < 5
        elif recurrence == "custom":
            matches = candidate.weekday() in selected_days
        else:
            matches = False

        if matches and candidate > after:
            return candidate

    return current_due + timedelta(days=1)


def complete_task(task_id: int, user_id: int) -> None:
    completed_at = now_local()
    with db() as conn:
        task = conn.execute(
            "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
            (task_id, user_id),
        ).fetchone()
        if not task:
            return

        current_due = parse_dt(task["due_at"]) or completed_at
        next_due = next_due_for_recurrence(
            current_due,
            task["recurrence"],
            task["recurrence_days"],
            completed_at,
        )

        if next_due:
            conn.execute(
                """
                UPDATE tasks
                SET due_at = ?, status = 'pending', last_completed_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    next_due.isoformat(timespec="minutes"),
                    completed_at.isoformat(timespec="minutes"),
                    task_id,
                    user_id,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE tasks
                SET status = 'done', last_completed_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (completed_at.isoformat(timespec="minutes"), task_id, user_id),
            )

        conn.execute(
            """
            UPDATE notifications
            SET answered_at = ?, answer = 'yes'
            WHERE task_id = ? AND answered_at IS NULL
            """,
            (completed_at.isoformat(timespec="minutes"), task_id),
        )


def notification_message(task: sqlite3.Row, reminder_count: int) -> str:
    due_at = format_due(task["due_at"])
    intro = "Напоминание" if reminder_count == 1 else f"Повторное напоминание #{reminder_count}"
    return f"{intro}: {task['title']} до {due_at}. Вы выполнили эту задачу?"


def generate_due_notifications() -> None:
    now = now_local()
    repeat_delta = timedelta(minutes=REMINDER_REPEAT_MINUTES)

    with db() as conn:
        tasks = conn.execute(
            """
            SELECT *
            FROM tasks
            WHERE status = 'pending'
            """
        ).fetchall()

        for task in tasks:
            due_at = parse_dt(task["due_at"])
            if not due_at:
                continue
            trigger_at = due_at - timedelta(minutes=int(task["remind_before_minutes"] or 0))
            if trigger_at > now:
                continue

            latest = conn.execute(
                """
                SELECT *
                FROM notifications
                WHERE task_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (task["id"],),
            ).fetchone()

            should_create = False
            reminder_count = 1
            if not latest:
                should_create = True
            elif latest["answered_at"]:
                latest_created = parse_dt(latest["created_at"]) or trigger_at
                if latest_created < trigger_at:
                    should_create = True
            else:
                latest_created = parse_dt(latest["created_at"]) or now
                if now - latest_created >= repeat_delta:
                    should_create = True
                    reminder_count = int(latest["reminder_count"] or 1) + 1

            if should_create:
                conn.execute(
                    """
                    INSERT INTO notifications (task_id, message, created_at, reminder_count)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        task["id"],
                        notification_message(task, reminder_count),
                        now.isoformat(timespec="minutes"),
                        reminder_count,
                    ),
                )


def create_task(form: dict[str, list[str]], user_id: int) -> None:
    title = first_value(form, "title")
    if not title:
        return

    due_date = first_value(form, "due_date", now_local().date().isoformat())
    due_time = first_value(form, "due_time", now_local().strftime("%H:%M"))
    due_at = parse_dt(f"{due_date}T{due_time}") or now_local()
    recurrence = first_value(form, "recurrence", "once")
    days = ",".join(form.get("days", []))

    with db() as conn:
        conn.execute(
            """
            INSERT INTO tasks (
                user_id, title, description, category, priority, due_at, remind_before_minutes,
                recurrence, recurrence_days, source, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                title,
                first_value(form, "description"),
                first_value(form, "category", "assignment"),
                first_value(form, "priority", "normal"),
                due_at.isoformat(timespec="minutes"),
                int(first_value(form, "remind_before_minutes", "0") or "0"),
                recurrence,
                days,
                first_value(form, "source", "manual"),
                now_local().isoformat(timespec="minutes"),
            ),
        )


def delete_task(task_id: int, user_id: int) -> None:
    with db() as conn:
        conn.execute(
            """
            DELETE FROM notifications
            WHERE task_id IN (
                SELECT id FROM tasks WHERE id = ? AND user_id = ?
            )
            """,
            (task_id, user_id),
        )
        conn.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id))


def answer_notification(notification_id: int, user_id: int) -> None:
    with db() as conn:
        notification = conn.execute(
            """
            SELECT notifications.*
            FROM notifications
            JOIN tasks ON tasks.id = notifications.task_id
            WHERE notifications.id = ? AND tasks.user_id = ?
            """,
            (notification_id, user_id),
        ).fetchone()
    if notification:
        complete_task(int(notification["task_id"]), user_id)


def fetch_tasks(sort_mode: str, user_id: int) -> list[sqlite3.Row]:
    order = "datetime(due_at) ASC"
    if sort_mode == "priority":
        order = """
        CASE priority
            WHEN 'high' THEN 0
            WHEN 'normal' THEN 1
            ELSE 2
        END,
        datetime(due_at) ASC
        """
    elif sort_mode == "recent":
        order = "datetime(created_at) DESC"

    with db() as conn:
        return conn.execute(
            f"""
            SELECT *
            FROM tasks
            WHERE status = 'pending' AND user_id = ?
            ORDER BY {order}
            """,
            (user_id,),
        ).fetchall()


def fetch_completed(user_id: int, limit: int = 8) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            """
            SELECT *
            FROM tasks
            WHERE status = 'done' AND user_id = ?
            ORDER BY datetime(last_completed_at) DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()


def fetch_unanswered_notifications(user_id: int) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            """
            SELECT n.*, t.title, t.priority, t.due_at
            FROM notifications n
            JOIN tasks t ON t.id = n.task_id
            WHERE n.answered_at IS NULL AND t.user_id = ?
            ORDER BY datetime(n.created_at) DESC, n.id DESC
            """,
            (user_id,),
        ).fetchall()


def render_select(name: str, options: dict[str, str], selected: str) -> str:
    items = []
    for value, label in options.items():
        mark = " selected" if value == selected else ""
        items.append(f'<option value="{escape(value)}"{mark}>{escape(label)}</option>')
    return f'<select name="{escape(name)}">{"".join(items)}</select>'


def render_task_item(task: sqlite3.Row, focus_id: str) -> str:
    priority = task["priority"]
    due = format_due(task["due_at"])
    description = escape(task["description"])
    focus_class = " is-focused" if focus_id == str(task["id"]) else ""
    recurrence = RECURRENCE_LABELS.get(task["recurrence"], task["recurrence"])
    category = CATEGORY_LABELS.get(task["category"], task["category"])
    source = SOURCE_LABELS.get(task["source"], task["source"])
    return f"""
    <article class="task-item{focus_class}" id="task-{task['id']}">
        <div class="task-main">
            <div class="task-title-row">
                <h3>{escape(task['title'])}</h3>
                <span class="badge {PRIORITY_BADGES.get(priority, 'priority-normal')}">{escape(PRIORITY_LABELS.get(priority, priority))}</span>
            </div>
            <p class="task-meta">{escape(category)} · {escape(source)} · {escape(recurrence)}</p>
            <p class="task-due">{escape(due)}</p>
            {f'<p class="task-description">{description}</p>' if description else ''}
        </div>
        <div class="task-actions">
            <form method="post" action="/tasks/{task['id']}/complete">
                <button class="icon-button done" title="Готово" aria-label="Готово">✓</button>
            </form>
            <form method="post" action="/tasks/{task['id']}/delete">
                <button class="icon-button delete" title="Удалить" aria-label="Удалить">×</button>
            </form>
        </div>
    </article>
    """


def render_notifications(notifications: list[sqlite3.Row]) -> str:
    if not notifications:
        return '<p class="empty">Нет активных напоминаний</p>'
    rows = []
    for item in notifications:
        rows.append(
            f"""
            <article class="notification">
                <p>{escape(item['message'])}</p>
                <form method="post" action="/notifications/{item['id']}/answer">
                    <button class="small-button">Да, выполнено</button>
                </form>
            </article>
            """
        )
    return "".join(rows)


def render_calendar(tasks: list[sqlite3.Row], year: int, month: int, sort_mode: str) -> str:
    by_day: dict[date, list[sqlite3.Row]] = {}
    for task in tasks:
        due_day = task_date(task["due_at"])
        if due_day:
            by_day.setdefault(due_day, []).append(task)

    cal = calendar.Calendar(firstweekday=0)
    weeks = cal.monthdatescalendar(year, month)
    prev_month = date(year, month, 1) - timedelta(days=1)
    next_month_seed = date(year, month, 28) + timedelta(days=4)
    next_month = date(next_month_seed.year, next_month_seed.month, 1)
    today = now_local().date()

    rows = []
    for week in weeks:
        cells = []
        for day in week:
            outside = " outside" if day.month != month else ""
            current = " today" if day == today else ""
            day_tasks = by_day.get(day, [])
            task_chips = "".join(
                f'<a class="calendar-chip {PRIORITY_BADGES.get(task["priority"], "priority-normal")}" href="#task-{task["id"]}">{escape(task["title"])}</a>'
                for task in day_tasks[:3]
            )
            more = f'<span class="more">+{len(day_tasks) - 3}</span>' if len(day_tasks) > 3 else ""
            cells.append(
                f"""
                <td class="calendar-day{outside}{current}">
                    <span class="day-number">{day.day}</span>
                    <div class="day-tasks">{task_chips}{more}</div>
                </td>
                """
            )
        rows.append(f"<tr>{''.join(cells)}</tr>")

    prev_href = f"/?month={prev_month.year}-{prev_month.month:02d}&sort={quote_plus(sort_mode)}"
    next_href = f"/?month={next_month.year}-{next_month.month:02d}&sort={quote_plus(sort_mode)}"
    month_title = f"{MONTH_LABELS[month]} {year}"
    weekdays = "".join(f"<th>{day}</th>" for day in WEEKDAY_LABELS)

    return f"""
    <section class="calendar-panel">
        <div class="panel-heading">
            <a class="nav-link" href="{prev_href}" title="Предыдущий месяц">‹</a>
            <h2>{escape(month_title)}</h2>
            <a class="nav-link" href="{next_href}" title="Следующий месяц">›</a>
        </div>
        <table class="calendar">
            <thead><tr>{weekdays}</tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


def sort_link(label: str, mode: str, current: str, month: str) -> str:
    active = " active" if mode == current else ""
    return f'<a class="sort-link{active}" href="/?sort={quote_plus(mode)}&month={quote_plus(month)}">{escape(label)}</a>'


def render_auth(mode: str, error: str = "") -> str:
    is_register = mode == "register"
    title = "Создать аккаунт" if is_register else "Войти"
    action = "/register" if is_register else "/login"
    switch_href = "/login" if is_register else "/register"
    switch_text = "Уже есть аккаунт? Войти" if is_register else "Нет аккаунта? Создать"
    subtitle = (
        "У каждого студента будет свой календарь, задачи и уведомления."
        if is_register
        else "Войди, чтобы открыть свой личный список задач."
    )
    error_html = f'<p class="auth-error">{escape(error)}</p>' if error else ""

    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(title)} · {APP_NAME}</title>
    <style>
        :root {{
            --bg: #f6f7fb;
            --surface: #ffffff;
            --text: #171923;
            --muted: #667085;
            --line: #d9dee8;
            --blue: #2f6bff;
            --red: #d92d20;
            font-family: Arial, Helvetica, sans-serif;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: var(--bg);
            color: var(--text);
            padding: 20px;
        }}
        .auth-card {{
            width: min(420px, 100%);
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 26px;
            box-shadow: 0 12px 30px rgba(21, 30, 55, 0.08);
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 22px;
        }}
        .brand-mark {{
            width: 38px;
            height: 38px;
            border-radius: 8px;
            background: var(--blue);
            color: #ffffff;
            display: grid;
            place-items: center;
            font-weight: 700;
        }}
        h1 {{
            margin: 0;
            font-size: 24px;
        }}
        p {{
            margin: 8px 0 0;
            color: var(--muted);
            line-height: 1.4;
        }}
        form {{
            display: grid;
            gap: 12px;
            margin-top: 20px;
        }}
        label {{
            display: grid;
            gap: 6px;
            color: var(--muted);
            font-size: 13px;
        }}
        input {{
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #ffffff;
            color: var(--text);
            padding: 11px;
            min-height: 42px;
            font: inherit;
        }}
        button {{
            border: 0;
            border-radius: 8px;
            background: var(--blue);
            color: #ffffff;
            cursor: pointer;
            font: inherit;
            font-weight: 700;
            padding: 12px 14px;
        }}
        .auth-error {{
            color: var(--red);
            background: #fff1f0;
            border: 1px solid #f5c2bc;
            border-radius: 8px;
            padding: 10px;
        }}
        .switch {{
            display: inline-block;
            margin-top: 16px;
            color: var(--blue);
            font-weight: 700;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <main class="auth-card">
        <div class="brand">
            <div class="brand-mark">U</div>
            <h1>{APP_NAME}</h1>
        </div>
        <h1>{escape(title)}</h1>
        <p>{escape(subtitle)}</p>
        {error_html}
        <form method="post" action="{action}">
            <label>Логин
                <input name="username" autocomplete="username" required>
            </label>
            <label>Пароль
                <input type="password" name="password" autocomplete="current-password" required>
            </label>
            <button>{escape(title)}</button>
        </form>
        <a class="switch" href="{switch_href}">{escape(switch_text)}</a>
    </main>
</body>
</html>"""


def render_home(user: sqlite3.Row, query: dict[str, list[str]]) -> str:
    generate_due_notifications()

    sort_mode = first_value(query, "sort", "time")
    if sort_mode not in {"time", "priority", "recent"}:
        sort_mode = "time"

    current_month_value = first_value(query, "month", now_local().strftime("%Y-%m"))
    try:
        year_text, month_text = current_month_value.split("-", 1)
        selected_year = int(year_text)
        selected_month = int(month_text)
        date(selected_year, selected_month, 1)
    except (ValueError, TypeError):
        selected_year = now_local().year
        selected_month = now_local().month
        current_month_value = now_local().strftime("%Y-%m")

    focus_id = first_value(query, "focus", "")
    user_id = int(user["id"])
    tasks = fetch_tasks(sort_mode, user_id)
    completed = fetch_completed(user_id)
    notifications = fetch_unanswered_notifications(user_id)
    default_due = now_local() + timedelta(hours=1)

    task_items = "".join(render_task_item(task, focus_id) for task in tasks)
    if not task_items:
        task_items = '<p class="empty">Пока нет задач</p>'

    completed_items = "".join(
        f"<li>{escape(task['title'])}<span>{escape(format_due(task['due_at']))}</span></li>"
        for task in completed
    )
    if not completed_items:
        completed_items = '<li class="muted">Нет выполненных задач</li>'

    browser_notification_button = """
        <button type="button" class="secondary-button" id="notify-permission">Включить push</button>
    """

    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{APP_NAME}</title>
    <style>
        :root {{
            --bg: #f6f7fb;
            --surface: #ffffff;
            --text: #171923;
            --muted: #667085;
            --line: #d9dee8;
            --blue: #2f6bff;
            --green: #138a4d;
            --amber: #b86b00;
            --red: #d92d20;
            --shadow: 0 12px 30px rgba(21, 30, 55, 0.08);
            font-family: Arial, Helvetica, sans-serif;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: var(--bg);
            color: var(--text);
        }}
        a {{ color: inherit; text-decoration: none; }}
        button, input, select, textarea {{
            font: inherit;
        }}
        .app-shell {{
            min-height: 100vh;
            display: grid;
            grid-template-columns: 280px minmax(0, 1fr);
        }}
        .sidebar {{
            background: #ffffff;
            border-right: 1px solid var(--line);
            padding: 24px;
            position: sticky;
            top: 0;
            height: 100vh;
            overflow-y: auto;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 26px;
        }}
        .brand-mark {{
            width: 38px;
            height: 38px;
            border-radius: 8px;
            background: var(--blue);
            color: #ffffff;
            display: grid;
            place-items: center;
            font-weight: 700;
        }}
        .brand h1 {{
            margin: 0;
            font-size: 22px;
            line-height: 1.1;
        }}
        .form-stack {{
            display: grid;
            gap: 12px;
        }}
        label {{
            display: grid;
            gap: 6px;
            color: var(--muted);
            font-size: 13px;
        }}
        input, select, textarea {{
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #ffffff;
            color: var(--text);
            padding: 10px 11px;
            min-height: 42px;
        }}
        textarea {{
            min-height: 76px;
            resize: vertical;
        }}
        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }}
        .weekday-picker {{
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 4px;
        }}
        .weekday-picker label {{
            display: block;
        }}
        .weekday-picker input {{
            position: absolute;
            opacity: 0;
            pointer-events: none;
        }}
        .weekday-picker span {{
            display: grid;
            place-items: center;
            min-height: 30px;
            border: 1px solid var(--line);
            border-radius: 7px;
            color: var(--muted);
            background: #fafbff;
            font-size: 12px;
        }}
        .weekday-picker input:checked + span {{
            background: var(--blue);
            border-color: var(--blue);
            color: #ffffff;
        }}
        .primary-button, .secondary-button, .small-button {{
            border: 0;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 700;
        }}
        .primary-button {{
            background: var(--blue);
            color: #ffffff;
            padding: 12px 14px;
            width: 100%;
        }}
        .secondary-button {{
            background: #eef3ff;
            color: #1f50c7;
            padding: 10px 12px;
            width: 100%;
            margin-top: 12px;
        }}
        .small-button {{
            background: var(--green);
            color: #ffffff;
            padding: 8px 10px;
            white-space: nowrap;
        }}
        .main {{
            padding: 26px;
            display: grid;
            gap: 20px;
        }}
        .topbar {{
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: center;
        }}
        .account-box {{
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--muted);
            font-size: 14px;
        }}
        .logout-button {{
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #ffffff;
            color: var(--blue);
            cursor: pointer;
            font-weight: 700;
            padding: 8px 10px;
        }}
        .topbar h2 {{
            margin: 0;
            font-size: 28px;
        }}
        .sort-tabs {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .sort-link {{
            padding: 9px 12px;
            border: 1px solid var(--line);
            border-radius: 8px;
            color: var(--muted);
            background: #ffffff;
        }}
        .sort-link.active {{
            border-color: var(--blue);
            color: var(--blue);
            background: #eef3ff;
            font-weight: 700;
        }}
        .content-grid {{
            display: grid;
            grid-template-columns: minmax(0, 1.3fr) minmax(320px, 0.7fr);
            gap: 20px;
            align-items: start;
        }}
        .panel, .calendar-panel {{
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 8px;
            box-shadow: var(--shadow);
        }}
        .panel {{
            padding: 18px;
        }}
        .panel-heading {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 14px;
        }}
        .panel-heading h2, .panel h2 {{
            margin: 0;
            font-size: 18px;
        }}
        .nav-link {{
            width: 34px;
            height: 34px;
            border: 1px solid var(--line);
            border-radius: 8px;
            display: grid;
            place-items: center;
            color: var(--blue);
            font-size: 24px;
            line-height: 1;
            background: #ffffff;
        }}
        .calendar-panel {{
            padding: 18px;
        }}
        .calendar {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }}
        .calendar th {{
            height: 32px;
            color: var(--muted);
            font-size: 12px;
            text-align: left;
            padding: 0 6px;
        }}
        .calendar-day {{
            height: 112px;
            vertical-align: top;
            border: 1px solid var(--line);
            padding: 7px;
            background: #ffffff;
        }}
        .calendar-day.outside {{
            background: #f8f9fc;
            color: #98a2b3;
        }}
        .calendar-day.today {{
            box-shadow: inset 0 0 0 2px var(--blue);
        }}
        .day-number {{
            display: inline-grid;
            place-items: center;
            width: 24px;
            height: 24px;
            border-radius: 7px;
            font-weight: 700;
            font-size: 13px;
        }}
        .day-tasks {{
            display: grid;
            gap: 4px;
            margin-top: 5px;
        }}
        .calendar-chip {{
            display: block;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            border-radius: 6px;
            padding: 4px 6px;
            font-size: 12px;
            color: #ffffff;
        }}
        .more {{
            color: var(--muted);
            font-size: 12px;
        }}
        .task-list {{
            display: grid;
            gap: 10px;
        }}
        .task-item {{
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 12px;
            align-items: start;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #ffffff;
        }}
        .task-item.is-focused {{
            border-color: var(--blue);
            box-shadow: 0 0 0 3px #dbe6ff;
        }}
        .task-title-row {{
            display: flex;
            justify-content: space-between;
            gap: 10px;
            align-items: start;
        }}
        .task-title-row h3 {{
            margin: 0;
            font-size: 16px;
            line-height: 1.25;
        }}
        .badge {{
            border-radius: 999px;
            color: #ffffff;
            padding: 4px 8px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }}
        .priority-high {{ background: var(--red); }}
        .priority-normal {{ background: var(--blue); }}
        .priority-low {{ background: var(--green); }}
        .task-meta, .task-description, .task-due {{
            margin: 6px 0 0;
        }}
        .task-meta, .task-description {{
            color: var(--muted);
            font-size: 13px;
        }}
        .task-due {{
            color: var(--amber);
            font-weight: 700;
            font-size: 14px;
        }}
        .task-actions {{
            display: flex;
            gap: 6px;
        }}
        .icon-button {{
            width: 34px;
            height: 34px;
            display: grid;
            place-items: center;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #ffffff;
            cursor: pointer;
            font-size: 20px;
            line-height: 1;
        }}
        .icon-button.done {{
            color: var(--green);
        }}
        .icon-button.delete {{
            color: var(--red);
        }}
        .side-stack {{
            display: grid;
            gap: 20px;
        }}
        .notification {{
            border: 1px solid #f5c2bc;
            background: #fff6f4;
            border-radius: 8px;
            padding: 12px;
            display: grid;
            gap: 10px;
        }}
        .notification p {{
            margin: 0;
            color: #7a271a;
            font-size: 14px;
            line-height: 1.35;
        }}
        .history {{
            margin: 0;
            padding: 0;
            list-style: none;
            display: grid;
            gap: 8px;
        }}
        .history li {{
            display: flex;
            justify-content: space-between;
            gap: 10px;
            border-bottom: 1px solid var(--line);
            padding-bottom: 8px;
            font-size: 14px;
        }}
        .history span, .muted, .empty {{
            color: var(--muted);
        }}
        .empty {{
            margin: 0;
            font-size: 14px;
        }}
        @media (max-width: 980px) {{
            .app-shell {{
                grid-template-columns: 1fr;
            }}
            .sidebar {{
                position: static;
                height: auto;
                border-right: 0;
                border-bottom: 1px solid var(--line);
            }}
            .content-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        @media (max-width: 640px) {{
            .main, .sidebar {{
                padding: 16px;
            }}
            .topbar {{
                align-items: stretch;
                flex-direction: column;
            }}
            .account-box {{
                justify-content: space-between;
            }}
            .two-col {{
                grid-template-columns: 1fr;
            }}
            .calendar-day {{
                height: 86px;
                padding: 5px;
            }}
            .calendar-chip {{
                font-size: 11px;
            }}
            .task-item {{
                grid-template-columns: 1fr;
            }}
            .task-actions {{
                justify-content: flex-end;
            }}
        }}
    </style>
</head>
<body>
    <div class="app-shell">
        <aside class="sidebar">
            <div class="brand">
                <div class="brand-mark">U</div>
                <h1>{APP_NAME}</h1>
            </div>
            <form method="post" action="/tasks" class="form-stack">
                <label>Название
                    <input name="title" placeholder="Например: финальный экзамен" required>
                </label>
                <label>Описание
                    <textarea name="description" placeholder="Аудитория, ссылка, требования"></textarea>
                </label>
                <div class="two-col">
                    <label>Тип
                        {render_select("category", CATEGORY_LABELS, "assignment")}
                    </label>
                    <label>Важность
                        {render_select("priority", PRIORITY_LABELS, "normal")}
                    </label>
                </div>
                <div class="two-col">
                    <label>Дата
                        <input type="date" name="due_date" value="{default_due.date().isoformat()}" required>
                    </label>
                    <label>Время
                        <input type="time" name="due_time" value="{default_due.strftime('%H:%M')}" required>
                    </label>
                </div>
                <div class="two-col">
                    <label>Напомнить
                        <select name="remind_before_minutes">
                            <option value="0">В момент срока</option>
                            <option value="10">За 10 минут</option>
                            <option value="30">За 30 минут</option>
                            <option value="60">За 1 час</option>
                            <option value="1440">За 1 день</option>
                        </select>
                    </label>
                    <label>Повтор
                        {render_select("recurrence", RECURRENCE_LABELS, "once")}
                    </label>
                </div>
                <label>Дни
                    <div class="weekday-picker">
                        {''.join(f'<label><input type="checkbox" name="days" value="{idx}"><span>{day}</span></label>' for idx, day in enumerate(WEEKDAY_LABELS))}
                    </div>
                </label>
                <label>Источник
                    {render_select("source", SOURCE_LABELS, "manual")}
                </label>
                <button class="primary-button">Добавить задачу</button>
            </form>
            {browser_notification_button}
        </aside>
        <main class="main">
            <header class="topbar">
                <h2>Задачи и календарь</h2>
                <div class="account-box">
                    <span>@{escape(user['username'])}</span>
                    <form method="post" action="/logout">
                        <button class="logout-button">Выйти</button>
                    </form>
                </div>
                <nav class="sort-tabs">
                    {sort_link("По времени", "time", sort_mode, current_month_value)}
                    {sort_link("По важности", "priority", sort_mode, current_month_value)}
                    {sort_link("Недавно", "recent", sort_mode, current_month_value)}
                </nav>
            </header>
            <div class="content-grid">
                <div class="panel-stack">
                    {render_calendar(tasks, selected_year, selected_month, sort_mode)}
                    <section class="panel" style="margin-top: 20px;">
                        <div class="panel-heading">
                            <h2>Список задач</h2>
                        </div>
                        <div class="task-list">{task_items}</div>
                    </section>
                </div>
                <aside class="side-stack">
                    <section class="panel">
                        <div class="panel-heading">
                            <h2>Уведомления</h2>
                        </div>
                        <div id="notifications">{render_notifications(notifications)}</div>
                    </section>
                    <section class="panel">
                        <div class="panel-heading">
                            <h2>Выполнено</h2>
                        </div>
                        <ul class="history">{completed_items}</ul>
                    </section>
                </aside>
            </div>
        </main>
    </div>
    <script>
        const notificationButton = document.getElementById("notify-permission");
        const seenKey = "unitask_seen_notifications_{int(user['id'])}";

        function readSeen() {{
            try {{
                return JSON.parse(localStorage.getItem(seenKey) || "[]");
            }} catch (error) {{
                return [];
            }}
        }}

        function writeSeen(items) {{
            localStorage.setItem(seenKey, JSON.stringify(items.slice(-100)));
        }}

        async function askPermission() {{
            if (!("Notification" in window)) {{
                return;
            }}
            await Notification.requestPermission();
        }}

        async function pollNotifications() {{
            try {{
                const response = await fetch("/api/notifications");
                const data = await response.json();
                const seen = readSeen();
                for (const item of data.notifications) {{
                    const id = String(item.id);
                    if (seen.includes(id)) {{
                        continue;
                    }}
                    seen.push(id);
                    if ("Notification" in window && Notification.permission === "granted") {{
                        const note = new Notification("UniTask", {{ body: item.message }});
                        note.onclick = () => {{
                            window.focus();
                            window.location.href = "/?focus=" + encodeURIComponent(item.task_id);
                        }};
                    }}
                }}
                writeSeen(seen);
            }} catch (error) {{
                return;
            }}
        }}

        notificationButton.addEventListener("click", askPermission);
        pollNotifications();
        setInterval(pollNotifications, 15000);
    </script>
</body>
</html>"""


class UniTaskHandler(BaseHTTPRequestHandler):
    server_version = "UniTask/1.0"

    def session_token(self) -> str | None:
        raw_cookie = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        cookie.load(raw_cookie)
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def current_user(self) -> sqlite3.Row | None:
        return get_user_by_session(self.session_token())

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)

        if path == "/login":
            self.send_html(render_auth("login", first_value(query, "error")))
        elif path == "/register":
            self.send_html(render_auth("register", first_value(query, "error")))
        elif path == "/":
            user = self.current_user()
            if not user:
                self.redirect("/login")
                return
            self.send_html(render_home(user, query))
        elif path == "/api/notifications":
            user = self.current_user()
            if not user:
                self.send_json({"error": "auth_required"}, status=HTTPStatus.UNAUTHORIZED)
                return
            generate_due_notifications()
            notifications = fetch_unanswered_notifications(int(user["id"]))
            payload = {
                "notifications": [
                    {
                        "id": item["id"],
                        "task_id": item["task_id"],
                        "message": item["message"],
                        "created_at": item["created_at"],
                    }
                    for item in notifications
                ]
            }
            self.send_json(payload)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        form = self.read_form()

        if path == "/register":
            user, error = create_user(
                first_value(form, "username"),
                first_value(form, "password"),
            )
            if error or not user:
                self.send_html(render_auth("register", error or "Не удалось создать аккаунт."))
                return
            token = create_session(int(user["id"]))
            self.redirect("/", cookies=[self.session_cookie_header(token)])
            return

        if path == "/login":
            user = authenticate_user(
                first_value(form, "username"),
                first_value(form, "password"),
            )
            if not user:
                self.send_html(render_auth("login", "Неверный логин или пароль."))
                return
            token = create_session(int(user["id"]))
            self.redirect("/", cookies=[self.session_cookie_header(token)])
            return

        if path == "/logout":
            delete_session(self.session_token())
            self.redirect("/login", cookies=[self.clear_session_cookie_header()])
            return

        user = self.current_user()
        if not user:
            self.redirect("/login")
            return
        user_id = int(user["id"])

        if path == "/tasks":
            create_task(form, user_id)
            self.redirect("/")
            return

        if path.startswith("/tasks/") and path.endswith("/complete"):
            task_id = self.path_id(path, prefix="/tasks/", suffix="/complete")
            if task_id is not None:
                complete_task(task_id, user_id)
            self.redirect("/")
            return

        if path.startswith("/tasks/") and path.endswith("/delete"):
            task_id = self.path_id(path, prefix="/tasks/", suffix="/delete")
            if task_id is not None:
                delete_task(task_id, user_id)
            self.redirect("/")
            return

        if path.startswith("/notifications/") and path.endswith("/answer"):
            notification_id = self.path_id(path, prefix="/notifications/", suffix="/answer")
            if notification_id is not None:
                answer_notification(notification_id, user_id)
            self.redirect("/")
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")

    def read_form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return parse_qs(raw, keep_blank_values=True)

    @staticmethod
    def path_id(path: str, prefix: str, suffix: str) -> int | None:
        value = path.removeprefix(prefix).removesuffix(suffix).strip("/")
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def session_cookie_header(token: str) -> str:
        max_age = SESSION_DAYS * 24 * 60 * 60
        return (
            f"{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age}; "
            "HttpOnly; SameSite=Lax"
        )

    @staticmethod
    def clear_session_cookie_header() -> str:
        return f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"

    def redirect(self, location: str, cookies: list[str] | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def send_html(self, html: str) -> None:
        encoded = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {self.address_string()} {fmt % args}")


def reminder_loop() -> None:
    while True:
        try:
            generate_due_notifications()
        except Exception as exc:
            print(f"Reminder worker error: {exc}")
        time.sleep(15)


def local_network_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "YOUR_LOCAL_IP"


def main() -> None:
    init_db()
    worker = threading.Thread(target=reminder_loop, daemon=True)
    worker.start()
    server = ThreadingHTTPServer((HOST, PORT), UniTaskHandler)
    lan_ip = local_network_ip()
    print(f"{APP_NAME} запущен")
    print(f"На этом компьютере: http://127.0.0.1:{PORT}")
    print(f"Для других устройств в этой Wi-Fi сети: http://{lan_ip}:{PORT}")
    print(f"Повтор напоминаний: каждые {REMINDER_REPEAT_MINUTES} минут")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка сервера")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
