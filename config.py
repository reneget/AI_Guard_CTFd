from CTFd.utils import get_config, set_config

PREFIX = "ai_guard_"

MAX_SCORE = 10.0

DEFAULT_NOTICE_TITLE = "Hidden by AI Guard"

DEFAULT_NOTICE_TEXT = (
    "Our fair-play system detected activity typical of automated AI-assisted "
    "solving and hid {account} from the scoreboard. This is not a final decision: "
    "please open a ticket with the organizers to resolve it."
)

DEFAULT_NOTICE_BANNER = "{title}. Please open a ticket with the organizers."

DEFAULT_SHAME_TITLE = "Wall of Shame"

DEFAULT_SHAME_TEXT = (
    "By decision of the organizers, these participants used AI to solve challenges "
    "automatically. They are excluded from the scoreboard and can no longer submit flags."
)

DEFAULT_SHAME_NOTICE_TITLE = "Wall of Shame"

DEFAULT_SHAME_NOTICE_TEXT = (
    "By decision of the organizers, {account} is on the wall of shame for using AI to "
    "solve challenges automatically. Flag submission is disabled and the results are "
    "excluded from the scoreboard."
)

DEFAULT_SHAME_BLOCKED = (
    "Flag submission is disabled: {account} is on the wall of shame."
)

# name -> (type, default, min, max)
SETTINGS = {
    "enabled": (bool, True, None, None),
    "auto_hide": (bool, True, None, None),
    "threshold": (float, 7.0, 0.5, MAX_SCORE),
    # Parallel / mass solving: >= burst_count solves by one account within burst_window seconds
    "burst_window": (int, 300, 10, 86400),
    "burst_count": (int, 5, 2, 1000),
    "burst_weight": (float, 3.0, 0.0, MAX_SCORE),
    # Small time delta between two solves of the same participant
    "delta_threshold": (int, 60, 1, 86400),
    "delta_weight": (float, 1.5, 0.0, MAX_SCORE),
    "delta_critical": (int, 15, 0, 86400),
    "delta_critical_weight": (float, 3.0, 0.0, MAX_SCORE),
    # Honeypot flag submitted
    "honeypot_weight": (float, 6.0, 0.0, MAX_SCORE),
    # Correct flag submitted with an API access token instead of a browser session
    "token_weight": (float, 1.5, 0.0, MAX_SCORE),
    # Challenge solved shortly after the account opened it for the first time.
    # Challenges worth less than view_min_value points (sanity checks, warm-ups) are skipped.
    "view_threshold": (int, 120, 1, 86400),
    "view_weight": (float, 1.5, 0.0, MAX_SCORE),
    "view_critical": (int, 30, 0, 86400),
    "view_critical_weight": (float, 3.0, 0.0, MAX_SCORE),
    "view_min_value": (int, 100, 0, 1000000),
    # Texts shown to a hidden account. Empty texts fall back to defaults().
    "notice_title": (str, "", None, None),
    "notice_text": (str, "", None, None),
    "notice_banner": (str, "", None, None),
    "ticket_url": (str, "", None, None),
    # Public wall of shame page (/wall-of-shame) and texts shown to shamed accounts
    "shame_enabled": (bool, False, None, None),
    "shame_title": (str, "", None, None),
    "shame_text": (str, "", None, None),
    "shame_notice_title": (str, "", None, None),
    "shame_notice_text": (str, "", None, None),
    "shame_blocked": (str, "", None, None),
    # Admin notifications
    "webhook_url": (str, "", None, None),
    "telegram_token": (str, "", None, None),
    "telegram_chat_id": (str, "", None, None),
    "admin_emails": (str, "", None, None),
    "external_only_hide": (bool, False, None, None),
}


# Texts saved from the "wall of shame" tab
SHAME_TEXTS = (
    "shame_title",
    "shame_text",
    "shame_notice_title",
    "shame_notice_text",
    "shame_blocked",
)

# Saved from the "wall of shame" tab, not from the general settings form
SHAME_SETTINGS = ("shame_enabled",) + SHAME_TEXTS


def get(name):
    kind, default, low, high = SETTINGS[name]
    value = get_config(PREFIX + name, default=None)
    if value is None:
        return default
    try:
        if kind is bool:
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "on", "yes")
            return bool(value)
        if kind is str:
            return str(value)
        value = kind(value)
    except (TypeError, ValueError):
        return default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def set(name, value):
    kind, _default, low, high = SETTINGS[name]
    if kind is bool:
        value = "true" if value else "false"
    elif kind is str:
        value = (value or "").strip()
    else:
        value = kind(value)
        if low is not None:
            value = max(low, value)
        if high is not None:
            value = min(high, value)
        value = str(value)
    set_config(PREFIX + name, value)


def all_settings():
    return {name: get(name) for name in SETTINGS}


def defaults(teams_mode):
    """Default texts shown to participants, worded for the current user mode."""
    account = "your team" if teams_mode else "your account"
    return {
        "notice_title": DEFAULT_NOTICE_TITLE,
        "notice_text": DEFAULT_NOTICE_TEXT.format(account=account),
        "notice_banner": DEFAULT_NOTICE_BANNER.format(
            title=get("notice_title") or DEFAULT_NOTICE_TITLE
        ),
        "shame_title": DEFAULT_SHAME_TITLE,
        "shame_text": DEFAULT_SHAME_TEXT,
        "shame_notice_title": DEFAULT_SHAME_NOTICE_TITLE,
        "shame_notice_text": DEFAULT_SHAME_NOTICE_TEXT.format(account=account),
        "shame_blocked": DEFAULT_SHAME_BLOCKED.format(account=account),
    }


def text(name, teams_mode):
    """A participant-facing text: the organizers' version or the default one."""
    return get(name) or defaults(teams_mode)[name]
