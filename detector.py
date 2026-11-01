import datetime
import json
import logging

from flask import url_for
from sqlalchemy.exc import IntegrityError

from CTFd.cache import (
    cache,
    clear_standings,
    clear_team_session,
    clear_user_session,
)
from CTFd.models import Challenges, Solves, Teams, Users, db
from CTFd.utils.config import is_teams_mode
from CTFd.utils.dates import ctftime

from . import config, kinds, notify
from .flags import find_honeypot
from .models import (
    AIGuardEvent,
    AIGuardNotice,
    AIGuardShame,
    AIGuardState,
    AIGuardView,
    utcnow,
)

log = logging.getLogger("ai_guard")


# ---------------------------------------------------------------------------
# Account helpers. An "account" is a team in teams mode and a user in users mode.
# ---------------------------------------------------------------------------


def account_model():
    return Teams if is_teams_mode() else Users


def get_account(account_id):
    return account_model().query.filter_by(id=account_id).first()


def account_columns(account):
    if is_teams_mode():
        return {"team_id": account.id, "user_id": None}
    return {"team_id": None, "user_id": account.id}


def account_clause(model, account_id):
    return (
        model.team_id == account_id if is_teams_mode() else model.user_id == account_id
    )


def account_id_column(model):
    return model.team_id if is_teams_mode() else model.user_id


def get_state(account, lock=False, create=True):
    def query(for_update=False):
        q = AIGuardState.query.filter(account_clause(AIGuardState, account.id))
        return (q.with_for_update() if for_update else q).first()

    # Create the row without locking: SELECT ... FOR UPDATE on a missing row takes a gap
    # lock in MySQL and two concurrent first solves would deadlock on the insert.
    state = query()
    if state is None and create:
        db.session.add(
            AIGuardState(
                score=0.0,
                whitelisted=False,
                auto_hidden=False,
                **account_columns(account),
            )
        )
        try:
            db.session.commit()
        except IntegrityError:
            # Created concurrently by another request
            db.session.rollback()
        state = query()
    if lock and state is not None:
        # The lock opens a new transaction, so every later read (e.g. MySQL's
        # REPEATABLE READ snapshot) sees what was committed before the lock was granted.
        db.session.commit()
        state = query(for_update=True)
    return state


def get_shame(account_id):
    return AIGuardShame.query.filter(account_clause(AIGuardShame, account_id)).first()


def clear_account_caches(account):
    if is_teams_mode():
        clear_team_session(team_id=account.id)
    else:
        clear_user_session(user_id=account.id)
    clear_standings()


def fmt_seconds(seconds):
    seconds = max(0.0, seconds)
    if seconds < 10:
        return f"{seconds:.1f} s"
    if seconds < 120:
        return f"{seconds:.0f} s"
    return f"{seconds / 60:.1f} min"


def challenge_points(challenge):
    """Nominal value of a challenge: the initial value for decaying (dynamic) ones."""
    if getattr(challenge, "function", "static") != "static" and challenge.initial:
        return challenge.initial
    return challenge.value or 0


# ---------------------------------------------------------------------------
# Challenge views
# ---------------------------------------------------------------------------


def record_view(user, team, challenge_id):
    """Remember when an account opened a challenge for the first time."""
    if user is None or user.type == "admin":
        return
    account = team if is_teams_mode() else user
    if account is None:
        return
    cache_key = (
        f"ai_guard_view_{'t' if is_teams_mode() else 'u'}_{account.id}_{challenge_id}"
    )
    if cache.get(cache_key):
        return
    exists = AIGuardView.query.filter(
        account_clause(AIGuardView, account.id),
        AIGuardView.challenge_id == challenge_id,
    ).first()
    if exists is None:
        db.session.add(
            AIGuardView(
                viewer_id=user.id,
                challenge_id=challenge_id,
                date=utcnow(),
                **account_columns(account),
            )
        )
        try:
            db.session.commit()
        except IntegrityError:
            # Another member opened it at the same moment
            db.session.rollback()
    cache.set(cache_key, True, timeout=3600)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _signal(kind, weight, summary, challenge_id=None, flag_id=None, **details):
    details["summary"] = summary
    return {
        "kind": kind,
        "weight": float(weight),
        "challenge_id": challenge_id,
        "flag_id": flag_id,
        "details": details,
    }


def detect_honeypot(account, user, challenge, submission):
    weight = config.get("honeypot_weight")
    if weight <= 0:
        return None
    flag = find_honeypot(challenge.id, submission)
    if flag is None:
        return None
    # Count every honeypot only once per account
    already = AIGuardEvent.query.filter(
        account_clause(AIGuardEvent, account.id),
        AIGuardEvent.kind == kinds.HONEYPOT,
        AIGuardEvent.flag_id == flag.id,
    ).first()
    if already is not None:
        return None
    flag_challenge = Challenges.query.filter_by(id=flag.challenge_id).first()
    flag_challenge_name = (
        flag_challenge.name if flag_challenge else f"#{flag.challenge_id}"
    )
    summary = f'{user.name} submitted the honeypot flag of "{flag_challenge_name}"'
    if flag.challenge_id != challenge.id:
        summary += f' (sent to "{challenge.name}")'
    return _signal(
        kinds.HONEYPOT,
        weight,
        summary,
        challenge_id=challenge.id,
        flag_id=flag.id,
        submission=submission[:500],
        honeypot_challenge_id=flag.challenge_id,
    )


def detect_fast_delta(user, challenge, solve):
    previous = (
        Solves.query.filter(
            Solves.user_id == user.id, Solves.id != solve.id, Solves.date <= solve.date
        )
        .order_by(Solves.date.desc(), Solves.id.desc())
        .first()
    )
    if previous is None:
        return None
    delta = (solve.date - previous.date).total_seconds()
    if delta < config.get("delta_critical"):
        weight = config.get("delta_critical_weight")
        limit = config.get("delta_critical")
    elif delta < config.get("delta_threshold"):
        weight = config.get("delta_weight")
        limit = config.get("delta_threshold")
    else:
        return None
    if weight <= 0:
        return None
    previous_name = (
        previous.challenge.name if previous.challenge else f"#{previous.challenge_id}"
    )
    summary = (
        f'{user.name} solved "{challenge.name}" {fmt_seconds(delta)} '
        f'after "{previous_name}" (threshold {limit} s)'
    )
    return _signal(
        kinds.FAST_DELTA,
        weight,
        summary,
        challenge_id=challenge.id,
        delta=round(delta, 2),
        previous_challenge_id=previous.challenge_id,
    )


def detect_burst(account, state, challenge, solve):
    weight = config.get("burst_weight")
    if weight <= 0:
        return None
    window = config.get("burst_window")
    needed = config.get("burst_count")
    start = solve.date - datetime.timedelta(seconds=window)
    # Solves that already triggered a burst are not counted twice
    if state.last_burst_at is not None and state.last_burst_at > start:
        start = state.last_burst_at
    recent = Solves.query.filter(
        account_clause(Solves, account.id),
        Solves.date > start,
        Solves.date <= solve.date,
    ).all()
    if len(recent) < needed:
        return None
    state.last_burst_at = solve.date
    users = sorted({s.user_id for s in recent if s.user_id})
    span = (solve.date - min(s.date for s in recent)).total_seconds()
    summary = (
        f"{len(recent)} challenges solved within {fmt_seconds(span)} "
        f"(window {window} s, members: {len(users)})"
    )
    return _signal(
        kinds.BURST,
        weight,
        summary,
        challenge_id=challenge.id,
        solves=len(recent),
        span=round(span, 2),
        user_ids=users,
        challenge_ids=[s.challenge_id for s in recent],
    )


def detect_api_token(user, challenge, user_agent):
    weight = config.get("token_weight")
    if weight <= 0:
        return None
    summary = f'{user.name} submitted the flag of "{challenge.name}" with an API token'
    if user_agent:
        summary += f" ({user_agent[:80]})"
    return _signal(
        kinds.API_TOKEN,
        weight,
        summary,
        challenge_id=challenge.id,
        user_agent=(user_agent or "")[:300],
    )


def detect_quick_solve(account, user, challenge, solve):
    if challenge_points(challenge) < config.get("view_min_value"):
        return None
    view = AIGuardView.query.filter(
        account_clause(AIGuardView, account.id),
        AIGuardView.challenge_id == challenge.id,
    ).first()
    # Never opened (or opened only after solving): nothing to measure
    if view is None or view.date > solve.date:
        return None
    delta = (solve.date - view.date).total_seconds()
    if delta < config.get("view_critical"):
        weight = config.get("view_critical_weight")
        limit = config.get("view_critical")
    elif delta < config.get("view_threshold"):
        weight = config.get("view_weight")
        limit = config.get("view_threshold")
    else:
        return None
    if weight <= 0:
        return None
    summary = (
        f'{user.name} solved "{challenge.name}" {fmt_seconds(delta)} '
        f"after it was first opened (threshold {limit} s)"
    )
    if view.viewer_id and view.viewer_id != user.id and view.viewer is not None:
        summary += f"; first opened by {view.viewer.name}"
    return _signal(
        kinds.QUICK_SOLVE,
        weight,
        summary,
        challenge_id=challenge.id,
        delta=round(delta, 2),
        viewer_id=view.viewer_id,
    )


def detect(account, user, challenge, submission, status, state, via_token, user_agent):
    signals = [detect_honeypot(account, user, challenge, submission)]
    if status == "correct":
        solve = Solves.query.filter(
            account_clause(Solves, account.id), Solves.challenge_id == challenge.id
        ).first()
        if solve is not None:
            if via_token:
                signals.append(detect_api_token(user, challenge, user_agent))
            signals.append(detect_quick_solve(account, user, challenge, solve))
            signals.append(detect_fast_delta(user, challenge, solve))
            signals.append(detect_burst(account, state, challenge, solve))
    return [s for s in signals if s is not None]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def add_event(
    account,
    kind,
    weight,
    score_after,
    summary,
    actor=None,
    challenge_id=None,
    flag_id=None,
    acknowledged=False,
    **details,
):
    details["summary"] = summary
    event = AIGuardEvent(
        actor_id=actor.id if actor is not None else None,
        challenge_id=challenge_id,
        flag_id=flag_id,
        kind=kind,
        weight=float(weight),
        score_after=float(score_after),
        details=json.dumps(details, ensure_ascii=False),
        acknowledged=acknowledged,
        date=utcnow(),
        **account_columns(account),
    )
    db.session.add(event)
    return event


def hide_account(account, state, now):
    account.hidden = True
    state.auto_hidden = True
    state.hidden_at = now
    add_event(
        account,
        kinds.AUTO_HIDE,
        0,
        state.score,
        f"Hidden from the scoreboard: risk {state.score:.1f} ≥ threshold "
        f"{config.get('threshold'):.1f}",
    )
    db.session.add(
        AIGuardNotice(
            title=config.text("notice_title", is_teams_mode()),
            content=config.text("notice_text", is_teams_mode()),
            date=now,
            **account_columns(account),
        )
    )


def apply_signals(account, user, state, signals):
    now = utcnow()
    was_hidden = bool(account.hidden)
    events = []
    for s in signals:
        state.score = round(min(config.MAX_SCORE, state.score + s["weight"]), 2)
        events.append(
            add_event(
                account,
                s["kind"],
                s["weight"],
                state.score,
                s["details"].pop("summary"),
                actor=user,
                challenge_id=s["challenge_id"],
                flag_id=s["flag_id"],
                **s["details"],
            )
        )
    state.last_event_at = now
    state.updated_at = now

    hidden_now = False
    if (
        config.get("auto_hide")
        and state.score >= config.get("threshold")
        and not account.hidden
        and not account.banned
    ):
        hide_account(account, state, now)
        hidden_now = True

    db.session.commit()

    if hidden_now:
        clear_account_caches(account)

    try:
        alert_admins(account, state, events, hidden_now, was_hidden)
    except Exception:  # noqa: BLE001
        log.exception("AI Guard: failed to send admin notifications")

    return {
        "events": [e.id for e in events],
        "score": state.score,
        "hidden": hidden_now,
    }


def alert_admins(account, state, events, hidden_now, was_hidden):
    if config.get("external_only_hide") and not hidden_now:
        return
    # Once an account is out of the scoreboard further signals only go to the admin panel
    if was_hidden and not hidden_now:
        return
    noun = "Team" if is_teams_mode() else "User"
    lines = []
    if hidden_now:
        lines.append(
            f'🚫 AI Guard: {noun} "{account.name}" hidden from the scoreboard '
            f"(risk {state.score:.1f}/10, threshold {config.get('threshold'):.1f})"
        )
    else:
        lines.append(f'⚠️ AI Guard: {noun} "{account.name}" — risk {state.score:.1f}/10')
    for e in events:
        lines.append(
            f"• {kinds.label(e.kind)} (+{e.weight:g}): {e.details_dict.get('summary', '')}"
        )
    try:
        lines.append(
            url_for("ai_guard.account_detail", account_id=account.id, _external=True)
        )
    except RuntimeError:
        pass
    subject = f'[AI Guard] {noun} "{account.name}"' + (" hidden" if hidden_now else "")
    notify.send_external("\n".join(lines), subject=subject)


def process_attempt(
    user, team, challenge_id, submission, status, via_token=False, user_agent=None
):
    """Analyze a processed flag submission. Called after the attempt API has responded."""
    if not config.get("enabled") or not ctftime():
        return None
    if user is None or user.type == "admin":
        return None
    account = team if is_teams_mode() else user
    if account is None:
        return None
    challenge = Challenges.query.filter_by(id=challenge_id).first()
    if challenge is None:
        return None

    # The row lock serializes the analysis of concurrent solves of one account
    state = get_state(account, lock=True)
    if state is None or state.whitelisted:
        db.session.rollback()
        return None

    signals = detect(
        account, user, challenge, submission, status, state, via_token, user_agent
    )
    if not signals:
        db.session.rollback()
        return None
    return apply_signals(account, user, state, signals)


# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------


def admin_set_score(account, value, admin, note=""):
    state = get_state(account, lock=True)
    old = state.score
    state.score = round(max(0.0, min(config.MAX_SCORE, float(value))), 2)
    state.updated_at = utcnow()
    kind = kinds.RESET if state.score == 0 else kinds.MANUAL
    summary = f"{admin.name}: {old:.1f} → {state.score:.1f}"
    if note:
        summary += f" ({note})"
    add_event(
        account,
        kind,
        state.score - old,
        state.score,
        summary,
        actor=admin,
        acknowledged=True,
    )
    if state.score == 0:
        state.last_burst_at = utcnow()
    db.session.commit()


def admin_unhide(account, admin, reset=True):
    state = get_state(account, lock=True)
    account.hidden = False
    state.auto_hidden = False
    old = state.score
    if reset:
        state.score = 0.0
        state.last_burst_at = utcnow()
    state.updated_at = utcnow()
    summary = f"{admin.name}: restored to the scoreboard"
    if reset:
        summary += f", risk reset ({old:.1f} → 0)"
    add_event(
        account,
        kinds.UNHIDE,
        state.score - old,
        state.score,
        summary,
        actor=admin,
        acknowledged=True,
    )
    db.session.commit()
    clear_account_caches(account)


def admin_whitelist(account, admin, value):
    state = get_state(account, lock=True)
    state.whitelisted = bool(value)
    state.updated_at = utcnow()
    kind = kinds.WHITELIST if value else kinds.UNWHITELIST
    add_event(
        account,
        kind,
        0,
        state.score,
        f"{admin.name}: {kinds.label(kind).lower()}",
        actor=admin,
        acknowledged=True,
    )
    db.session.commit()


def admin_shame(account, admin, comment=""):
    """Put an account on the wall of shame: hide it and block further submissions."""
    if get_shame(account.id) is not None:
        return False
    state = get_state(account, lock=True)
    now = utcnow()
    db.session.add(
        AIGuardShame(
            admin_id=admin.id,
            comment=comment or None,
            date=now,
            **account_columns(account),
        )
    )
    account.hidden = True
    state.updated_at = now
    summary = f"{admin.name}: put on the wall of shame"
    if comment:
        summary += f" ({comment})"
    add_event(
        account, kinds.SHAME, 0, state.score, summary, actor=admin, acknowledged=True
    )
    db.session.add(
        AIGuardNotice(
            title=config.text("shame_notice_title", is_teams_mode()),
            content=config.text("shame_notice_text", is_teams_mode()),
            date=now,
            **account_columns(account),
        )
    )
    try:
        db.session.commit()
    except IntegrityError:
        # Shamed concurrently by another admin
        db.session.rollback()
        return False
    clear_account_caches(account)
    return True


def admin_unshame(account, admin):
    """Remove an account from the wall of shame. It stays hidden from the scoreboard."""
    shame = get_shame(account.id)
    if shame is None:
        return False
    state = get_state(account, lock=True)
    db.session.delete(shame)
    state.updated_at = utcnow()
    add_event(
        account,
        kinds.UNSHAME,
        0,
        state.score,
        f"{admin.name}: removed from the wall of shame, flag submission allowed again",
        actor=admin,
        acknowledged=True,
    )
    db.session.commit()
    return True
