import logging
import threading

import requests
from flask import current_app

from . import config

log = logging.getLogger("ai_guard")


def _post(url, payload):
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:  # noqa: BLE001 - notifications must never break anything
        log.warning("AI Guard: notification to %s failed: %s", url.split("?")[0], e)


def _send(app, text, subject, targets):
    webhook_url, telegram_token, telegram_chat_id, emails = targets
    if webhook_url:
        # "content" is read by Discord, "text" by Slack / Mattermost / Rocket.Chat
        _post(
            webhook_url, {"content": text[:1900], "text": text, "username": "AI Guard"}
        )
    if telegram_token and telegram_chat_id:
        _post(
            f"https://api.telegram.org/bot{telegram_token}/sendMessage",
            {
                "chat_id": telegram_chat_id,
                "text": text[:4000],
                "disable_web_page_preview": True,
            },
        )
    if emails:
        from CTFd.utils.email import sendmail

        with app.app_context():
            for addr in emails:
                try:
                    sendmail(addr, text, subject)
                except Exception as e:  # noqa: BLE001
                    log.warning("AI Guard: email to %s failed: %s", addr, e)


def send_external(text, subject="[AI Guard] Suspicious activity"):
    """Deliver an admin alert to the configured external channels in the background."""
    targets = (
        config.get("webhook_url"),
        config.get("telegram_token"),
        config.get("telegram_chat_id"),
        [
            e.strip()
            for e in config.get("admin_emails").replace(";", ",").split(",")
            if e.strip()
        ],
    )
    if not any(targets):
        return False
    app = current_app._get_current_object()
    thread = threading.Thread(
        target=_send, args=(app, text, subject, targets), daemon=True
    )
    thread.start()
    return True
