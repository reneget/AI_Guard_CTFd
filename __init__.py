"""
AI Guard: detection of AI-assisted automated solving for CTFd.

Every account (team in teams mode, user in users mode) has an AI-risk score from 0 to 10.
Suspicious activity (mass solving, tiny time between flags of one participant, solving a
challenge right after opening it, submitting flags with an API token, honeypot flags)
raises the score. Organizers may also put an account on the public wall of shame, which
hides it and blocks further flag submissions. Once it reaches the threshold the account is hidden from the
scoreboard, its members get a private notice asking them to open a ticket, and the
organizers are alerted in the admin panel and (optionally) via webhook/Telegram/email.
"""

import logging
import os
import time

from flask import jsonify, request

from CTFd.models import db
from CTFd.plugins import (
    register_admin_plugin_menu_bar,
    register_admin_plugin_script,
    register_plugin_script,
)
from CTFd.plugins.flags import FLAG_CLASSES
from CTFd.plugins.migrations import upgrade
from CTFd.utils.config import is_teams_mode
from CTFd.utils.user import get_current_team, get_current_user

from . import (
    config,
    models,  # noqa: F401 - registers the tables before upgrade()
)
from .detector import get_shame, process_attempt, record_view
from .flags import HONEYPOT_FLAG_TYPE, HoneypotFlag
from .routes import ai_guard

log = logging.getLogger("ai_guard")

ATTEMPT_ENDPOINT = "api.challenges_challenge_attempt"
CHALLENGE_ENDPOINT = "api.challenges_challenge"
HANDLED_STATUSES = ("correct", "incorrect", "partial", "already_solved")


def block_shamed_attempts():
    """Accounts on the wall of shame can not submit flags anymore."""
    if request.method != "POST" or request.endpoint != ATTEMPT_ENDPOINT:
        return None
    try:
        user = get_current_user()
        if user is None or user.type == "admin":
            return None
        account = get_current_team() if is_teams_mode() else user
        if account is None or get_shame(account.id) is None:
            return None
    except Exception:  # noqa: BLE001 - fall back to CTFd's normal processing
        db.session.rollback()
        log.exception("AI Guard: failed to check the wall of shame")
        return None
    # "paused" is a status the CTFd themes already display as a warning
    message = config.text("shame_blocked", is_teams_mode())
    return jsonify(
        {"success": True, "data": {"status": "paused", "message": message}}
    ), 403


def after_challenge_view(response):
    if (
        request.method != "GET"
        or request.endpoint != CHALLENGE_ENDPOINT
        or response.status_code != 200
    ):
        return response
    try:
        data = (response.get_json(silent=True) or {}).get("data") or {}
        # Challenges locked behind prerequisites are returned anonymized
        if data.get("type") == "hidden" or data.get("id") is None:
            return response
        record_view(get_current_user(), get_current_team(), int(data["id"]))
    except Exception:  # noqa: BLE001 - never break challenge loading because of the plugin
        db.session.rollback()
        log.exception("AI Guard: failed to record challenge view")
    return response


def after_attempt(response):
    if request.method != "POST" or request.endpoint != ATTEMPT_ENDPOINT:
        return response
    try:
        result = response.get_json(silent=True) or {}
        status = (result.get("data") or {}).get("status")
        if status not in HANDLED_STATUSES:
            return response
        payload = (
            request.get_json(silent=True) if request.is_json else request.form
        ) or {}
        challenge_id = int(payload.get("challenge_id"))
        submission = str(payload.get("submission") or "").strip()
        # CTFd authenticates the request with an access token only for JSON requests
        # carrying an Authorization header (an invalid token is rejected with 401)
        via_token = request.is_json and bool(request.headers.get("Authorization"))
        process_attempt(
            get_current_user(),
            get_current_team(),
            challenge_id,
            submission,
            status,
            via_token=via_token,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:  # noqa: BLE001 - never break flag submission because of the plugin
        db.session.rollback()
        log.exception("AI Guard: failed to process submission")
    return response


def apply_migrations(attempts=5):
    # Every gunicorn worker loads the plugin, so with a pending migration several of them
    # may try to create the same table at once. The losing worker waits and retries: the
    # migrations skip tables that already exist.
    plugin_name = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
    for attempt in range(1, attempts + 1):
        try:
            upgrade(plugin_name=plugin_name)
            return
        except Exception:
            if attempt == attempts:
                raise
            db.session.rollback()
            log.warning("AI Guard: migration attempt %s failed, retrying", attempt)
            time.sleep(attempt)


def load(app):
    apply_migrations()

    FLAG_CLASSES[HONEYPOT_FLAG_TYPE] = HoneypotFlag

    app.register_blueprint(ai_guard)
    # Registered after CTFd's own handlers, so token authentication has already happened
    app.before_request(block_shamed_attempts)
    app.after_request(after_attempt)
    app.after_request(after_challenge_view)

    register_admin_plugin_menu_bar("AI Guard", "/admin/ai_guard")
    register_admin_plugin_script("/plugins/ai_guard/assets/admin.js")
    register_plugin_script("/plugins/ai_guard/assets/notice.js")
