import re

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy import func

from CTFd.models import Challenges, Flags, db
from CTFd.utils.config import is_teams_mode
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.user import get_current_team, get_current_user

from . import config, detector, kinds, notify
from .flags import HONEYPOT_FLAG_TYPE, MATCH_MODES
from .models import (
    AIGuardEvent,
    AIGuardNotice,
    AIGuardNoticeRead,
    AIGuardShame,
    AIGuardState,
)

ai_guard = Blueprint(
    "ai_guard",
    __name__,
    template_folder="templates",
    static_folder="assets",
    static_url_path="/plugins/ai_guard/assets",
)

EVENTS_PER_PAGE = 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def account_names(ids):
    ids = {i for i in ids if i is not None}
    if not ids:
        return {}
    model = detector.account_model()
    rows = (
        model.query.with_entities(model.id, model.name).filter(model.id.in_(ids)).all()
    )
    return {row.id: row.name for row in rows}


def event_account_id(event):
    return event.team_id if is_teams_mode() else event.user_id


def serialize_event(event, names):
    account_id = event_account_id(event)
    return {
        "id": event.id,
        "account_id": account_id,
        "account_name": names.get(account_id, f"#{account_id}"),
        "kind": event.kind,
        "label": kinds.label(event.kind),
        "weight": event.weight,
        "score_after": event.score_after,
        "summary": event.details_dict.get("summary", ""),
        "acknowledged": event.acknowledged,
        "date": event.date.isoformat() + "Z" if event.date else None,
        "url": url_for("ai_guard.account_detail", account_id=account_id),
    }


def unacked_query():
    return AIGuardEvent.query.filter(
        AIGuardEvent.acknowledged.is_(False),
        detector.account_id_column(AIGuardEvent).isnot(None),
    )


def admin_admin_url(account_id):
    if is_teams_mode():
        return url_for("admin.teams_detail", team_id=account_id)
    return url_for("admin.users_detail", user_id=account_id)


def common_context(tab):
    return {
        "tab": tab,
        "teams_mode": is_teams_mode(),
        "noun": "Team" if is_teams_mode() else "User",
        "threshold": config.get("threshold"),
        "unacked_count": unacked_query().count(),
        "label": kinds.label,
        "signal_kinds": kinds.SIGNALS,
        "admin_url": admin_admin_url,
        "shame_count": AIGuardShame.query.filter(
            detector.account_id_column(AIGuardShame).isnot(None)
        ).count(),
    }


def shamed_ids():
    column = detector.account_id_column(AIGuardShame)
    return {row[0] for row in db.session.query(column).filter(column.isnot(None)).all()}


def safe_next(default):
    target = request.form.get("next") or ""
    # Only allow local redirects
    if target.startswith("/") and not target.startswith("//"):
        return target
    return default


# ---------------------------------------------------------------------------
# Admin pages
# ---------------------------------------------------------------------------


@ai_guard.route("/admin/ai_guard")
@admins_only
def board():
    column = detector.account_id_column(AIGuardState)
    shamed = shamed_ids()
    states = (
        AIGuardState.query.filter(column.isnot(None))
        .filter(
            (AIGuardState.score > 0)
            | AIGuardState.whitelisted
            | AIGuardState.auto_hidden
            | column.in_(shamed or [-1])
        )
        .order_by(AIGuardState.score.desc(), AIGuardState.last_event_at.desc())
        .all()
    )
    account_ids = [getattr(s, column.key) for s in states]
    model = detector.account_model()
    accounts = (
        {a.id: a for a in model.query.filter(model.id.in_(account_ids)).all()}
        if account_ids
        else {}
    )

    event_column = detector.account_id_column(AIGuardEvent)
    signal_counts = dict(
        db.session.query(event_column, func.count(AIGuardEvent.id))
        .filter(
            event_column.in_(account_ids or [-1]), AIGuardEvent.kind.in_(kinds.SIGNALS)
        )
        .group_by(event_column)
        .all()
    )

    rows = []
    for s in states:
        account_id = getattr(s, column.key)
        account = accounts.get(account_id)
        if account is None:
            continue
        rows.append(
            {
                "state": s,
                "account": account,
                "signals": signal_counts.get(account_id, 0),
            }
        )

    threshold = config.get("threshold")
    stats = {
        "risky": sum(1 for r in rows if r["state"].score > 0),
        "over": sum(1 for r in rows if r["state"].score >= threshold),
        "auto_hidden": sum(
            1 for r in rows if r["state"].auto_hidden and r["account"].hidden
        ),
        "honeypots": Flags.query.filter_by(type=HONEYPOT_FLAG_TYPE).count(),
    }
    return render_template(
        "ai_guard/board.html",
        rows=rows,
        stats=stats,
        shamed=shamed,
        settings=config.all_settings(),
        **common_context("board"),
    )


@ai_guard.route("/admin/ai_guard/account/<int:account_id>")
@admins_only
def account_detail(account_id):
    account = detector.get_account(account_id)
    if account is None:
        abort(404)
    state = detector.get_state(account, create=False)
    events = (
        AIGuardEvent.query.filter(detector.account_clause(AIGuardEvent, account_id))
        .order_by(AIGuardEvent.id.desc())
        .all()
    )
    notices = (
        AIGuardNotice.query.filter(detector.account_clause(AIGuardNotice, account_id))
        .order_by(AIGuardNotice.id.desc())
        .all()
    )
    reads = {}
    if notices:
        for read in AIGuardNoticeRead.query.filter(
            AIGuardNoticeRead.notice_id.in_([n.id for n in notices])
        ).all():
            reads.setdefault(read.notice_id, []).append(read)
    members = account.members if is_teams_mode() else [account]
    return render_template(
        "ai_guard/account.html",
        account=account,
        state=state,
        shame=detector.get_shame(account_id),
        events=events,
        notices=notices,
        reads=reads,
        members={m.id: m.name for m in members},
        **common_context("board"),
    )


@ai_guard.route("/admin/ai_guard/account/<int:account_id>/action", methods=["POST"])
@admins_only
def account_action(account_id):
    account = detector.get_account(account_id)
    if account is None:
        abort(404)
    admin = get_current_user()
    action = request.form.get("action")
    if action == "reset":
        detector.admin_set_score(account, 0, admin)
        flash(f'Risk score of "{account.name}" reset', "success")
    elif action == "set":
        try:
            value = float(request.form.get("score", "").replace(",", "."))
        except ValueError:
            flash("Invalid score value", "danger")
        else:
            detector.admin_set_score(
                account, value, admin, note=request.form.get("note", "").strip()[:200]
            )
            flash(f'Risk score of "{account.name}" updated', "success")
    elif action == "unhide":
        if detector.get_shame(account_id) is not None:
            flash("Remove the account from the wall of shame first", "danger")
        else:
            detector.admin_unhide(
                account, admin, reset=request.form.get("reset") == "y"
            )
            flash(f'"{account.name}" restored to the scoreboard', "success")
    elif action == "shame":
        comment = (request.form.get("comment") or "").strip()[:500]
        if detector.admin_shame(account, admin, comment):
            flash(
                f'"{account.name}" is on the wall of shame: hidden from the '
                "scoreboard, flag submission disabled",
                "success",
            )
        else:
            flash(f'"{account.name}" is already on the wall of shame', "warning")
    elif action == "unshame":
        if detector.admin_unshame(account, admin):
            flash(
                f'"{account.name}" removed from the wall of shame and can submit flags '
                "again. It is still hidden from the scoreboard",
                "success",
            )
    elif action in ("whitelist", "unwhitelist"):
        detector.admin_whitelist(account, admin, action == "whitelist")
        flash(f'"{account.name}": {kinds.label(action).lower()}', "success")
    else:
        abort(400)
    return redirect(
        safe_next(url_for("ai_guard.account_detail", account_id=account_id))
    )


@ai_guard.route("/admin/ai_guard/events")
@admins_only
def events():
    only_new = request.args.get("filter") == "new"
    kind = request.args.get("kind") or None
    page = max(1, request.args.get("page", 1, type=int))
    column = detector.account_id_column(AIGuardEvent)
    query = AIGuardEvent.query.filter(column.isnot(None))
    if only_new:
        query = query.filter(AIGuardEvent.acknowledged.is_(False))
    if kind:
        query = query.filter(AIGuardEvent.kind == kind)
    pagination = query.order_by(AIGuardEvent.id.desc()).paginate(
        page=page, per_page=EVENTS_PER_PAGE, error_out=False
    )
    names = account_names(getattr(e, column.key) for e in pagination.items)
    return render_template(
        "ai_guard/events.html",
        pagination=pagination,
        names=names,
        only_new=only_new,
        kind=kind,
        all_kinds=kinds.LABELS,
        event_account_id=event_account_id,
        **common_context("events"),
    )


@ai_guard.route("/admin/ai_guard/events/ack", methods=["POST"])
@admins_only
def events_ack():
    unacked_query().update({AIGuardEvent.acknowledged: True}, synchronize_session=False)
    db.session.commit()
    flash("All alerts marked as read", "success")
    return redirect(safe_next(url_for("ai_guard.events")))


@ai_guard.route("/admin/ai_guard/honeypots")
@admins_only
def honeypots():
    flags = (
        Flags.query.filter_by(type=HONEYPOT_FLAG_TYPE)
        .order_by(Flags.challenge_id, Flags.id)
        .all()
    )
    hits = dict(
        db.session.query(AIGuardEvent.flag_id, func.count(AIGuardEvent.id))
        .filter(AIGuardEvent.kind == kinds.HONEYPOT)
        .group_by(AIGuardEvent.flag_id)
        .all()
    )
    challenges = Challenges.query.order_by(Challenges.category, Challenges.name).all()
    return render_template(
        "ai_guard/honeypots.html",
        flags=flags,
        hits=hits,
        challenges=challenges,
        challenge_map={c.id: c for c in challenges},
        match_modes=MATCH_MODES,
        honeypot_weight=config.get("honeypot_weight"),
        **common_context("honeypots"),
    )


@ai_guard.route("/admin/ai_guard/honeypots", methods=["POST"])
@admins_only
def honeypots_create():
    challenge = Challenges.query.filter_by(
        id=request.form.get("challenge_id", type=int)
    ).first()
    content = (request.form.get("content") or "").strip()
    mode = request.form.get("data", "")
    if challenge is None or not content or mode not in MATCH_MODES:
        flash("Choose a challenge, enter the flag and a matching mode", "danger")
        return redirect(url_for("ai_guard.honeypots"))
    if mode.startswith("regex"):
        try:
            re.compile(content)
        except re.error as e:
            flash(f"Invalid regular expression: {e}", "danger")
            return redirect(url_for("ai_guard.honeypots"))
    db.session.add(
        Flags(
            challenge_id=challenge.id,
            type=HONEYPOT_FLAG_TYPE,
            content=content,
            data=mode,
        )
    )
    db.session.commit()
    flash(f'Honeypot flag added to "{challenge.name}"', "success")
    if challenge.logic == "all":
        flash(
            f'"{challenge.name}" uses the "all" flag logic, so the honeypot becomes a '
            'mandatory part of the solution. Use the "any" logic for honeypot flags.',
            "warning",
        )
    return redirect(url_for("ai_guard.honeypots"))


@ai_guard.route("/admin/ai_guard/honeypots/<int:flag_id>/delete", methods=["POST"])
@admins_only
def honeypots_delete(flag_id):
    flag = Flags.query.filter_by(id=flag_id, type=HONEYPOT_FLAG_TYPE).first_or_404()
    db.session.delete(flag)
    db.session.commit()
    flash("Honeypot flag deleted", "success")
    return redirect(url_for("ai_guard.honeypots"))


@ai_guard.route("/admin/ai_guard/settings", methods=["GET", "POST"])
@admins_only
def settings():
    if request.method == "POST":
        errors = []
        for name, (kind, _default, _low, _high) in config.SETTINGS.items():
            if name in config.SHAME_SETTINGS:
                continue
            if kind is bool:
                config.set(name, request.form.get(name) == "y")
                continue
            raw = request.form.get(name)
            if raw is None:
                continue
            if kind is str:
                config.set(name, raw)
                continue
            try:
                config.set(
                    name, kind(raw.replace(",", ".")) if kind is float else kind(raw)
                )
            except ValueError:
                errors.append(name)
        if errors:
            flash("Invalid values were not saved: " + ", ".join(errors), "danger")
        else:
            flash("Settings saved", "success")
        return redirect(url_for("ai_guard.settings"))
    return render_template(
        "ai_guard/settings.html",
        settings=config.all_settings(),
        defaults=config.defaults(is_teams_mode()),
        **common_context("settings"),
    )


@ai_guard.route("/admin/ai_guard/settings/test", methods=["POST"])
@admins_only
def settings_test():
    sent = notify.send_external(
        "✅ AI Guard: test alert. If you can see this message, the channel works.",
        subject="[AI Guard] Test alert",
    )
    if sent:
        flash(
            "Test alert sent (check the channel; errors are written to the CTFd log)",
            "success",
        )
    else:
        flash("No external alert channel is configured", "warning")
    return redirect(url_for("ai_guard.settings"))


# ---------------------------------------------------------------------------
# Wall of shame
# ---------------------------------------------------------------------------


def shame_rows():
    model = detector.account_model()
    column = detector.account_id_column(AIGuardShame)
    return (
        db.session.query(AIGuardShame, model)
        .join(model, model.id == column)
        .order_by(AIGuardShame.date.desc(), AIGuardShame.id.desc())
        .all()
    )


@ai_guard.route("/admin/ai_guard/shame")
@admins_only
def shame_admin():
    return render_template(
        "ai_guard/shame.html",
        rows=shame_rows(),
        settings=config.all_settings(),
        defaults=config.defaults(is_teams_mode()),
        **common_context("shame"),
    )


@ai_guard.route("/admin/ai_guard/shame/settings", methods=["POST"])
@admins_only
def shame_settings():
    action = request.form.get("action")
    if action in ("enable", "disable"):
        config.set("shame_enabled", action == "enable")
        flash(
            "The wall of shame page is published"
            if action == "enable"
            else "The wall of shame page is hidden",
            "success",
        )
    else:
        for name in config.SHAME_TEXTS:
            if name in request.form:
                config.set(name, request.form[name])
        flash("Wall of shame texts saved", "success")
    return redirect(url_for("ai_guard.shame_admin"))


@ai_guard.route("/wall-of-shame")
def wall_of_shame():
    from CTFd.utils.user import is_admin

    enabled = config.get("shame_enabled")
    if not enabled and not is_admin():
        abort(404)
    return render_template(
        "ai_guard/wall.html",
        rows=shame_rows(),
        enabled=enabled,
        title=config.text("shame_title", is_teams_mode()),
        text=config.text("shame_text", is_teams_mode()),
        teams_mode=is_teams_mode(),
    )


# ---------------------------------------------------------------------------
# Admin JSON API (used by assets/admin.js on every admin page)
# ---------------------------------------------------------------------------


@ai_guard.route("/admin/ai_guard/api/alerts")
@admins_only
def api_alerts():
    after = request.args.get("after", type=int)
    latest = db.session.query(func.max(AIGuardEvent.id)).scalar() or 0
    data = []
    if after is not None:
        items = (
            unacked_query()
            .filter(AIGuardEvent.id > after)
            .order_by(AIGuardEvent.id.asc())
            .limit(20)
            .all()
        )
        names = account_names(event_account_id(e) for e in items)
        data = [serialize_event(e, names) for e in items]
    return jsonify(
        {
            "success": True,
            "data": data,
            "latest_id": latest,
            "unacked": unacked_query().count(),
            "page": url_for("ai_guard.events", filter="new"),
        }
    )


@ai_guard.route("/admin/ai_guard/api/alerts/ack", methods=["POST"])
@admins_only
def api_alerts_ack():
    payload = request.get_json(silent=True) or {}
    query = unacked_query()
    ids = payload.get("ids")
    if ids:
        query = query.filter(AIGuardEvent.id.in_([int(i) for i in ids]))
    query.update({AIGuardEvent.acknowledged: True}, synchronize_session=False)
    db.session.commit()
    return jsonify({"success": True, "unacked": unacked_query().count()})


@ai_guard.route("/admin/ai_guard/api/scores")
@admins_only
def api_scores():
    column = detector.account_id_column(AIGuardState)
    states = AIGuardState.query.filter(column.isnot(None)).all()
    shamed = shamed_ids()
    return jsonify(
        {
            "success": True,
            "mode": "teams" if is_teams_mode() else "users",
            "threshold": config.get("threshold"),
            "enabled": config.get("enabled"),
            "data": {
                getattr(s, column.key): {
                    "score": s.score,
                    "whitelisted": s.whitelisted,
                    "auto_hidden": s.auto_hidden,
                    "shamed": getattr(s, column.key) in shamed,
                    "url": url_for(
                        "ai_guard.account_detail", account_id=getattr(s, column.key)
                    ),
                }
                for s in states
            },
            "base_url": url_for("ai_guard.board"),
        }
    )


# ---------------------------------------------------------------------------
# Participant API (used by assets/notice.js)
# ---------------------------------------------------------------------------


def current_account():
    return get_current_team() if is_teams_mode() else get_current_user()


@ai_guard.route("/ai_guard/api/notice")
@authed_only
def api_notice():
    user = get_current_user()
    account = current_account()
    if account is None or user.type == "admin":
        return jsonify({"success": True, "data": None})
    state = detector.get_state(account, create=False)
    notices = (
        AIGuardNotice.query.filter(detector.account_clause(AIGuardNotice, account.id))
        .filter(
            ~AIGuardNotice.id.in_(
                db.session.query(AIGuardNoticeRead.notice_id).filter(
                    AIGuardNoticeRead.user_id == user.id
                )
            )
        )
        .order_by(AIGuardNotice.id.asc())
        .all()
    )
    shamed = detector.get_shame(account.id) is not None
    hidden = bool(state is not None and state.auto_hidden and account.hidden)
    if shamed:
        banner = config.text("shame_blocked", is_teams_mode())
    elif hidden:
        banner = config.text("notice_banner", is_teams_mode())
    else:
        banner = None
    return jsonify(
        {
            "success": True,
            "data": {
                "hidden": hidden or shamed,
                "shamed": shamed,
                "banner": banner,
                "ticket_url": config.get("ticket_url") or None,
                "notices": [
                    {
                        "id": n.id,
                        "title": n.title,
                        "content": n.content,
                        "date": n.date.isoformat() + "Z" if n.date else None,
                    }
                    for n in notices
                ],
            },
        }
    )


@ai_guard.route("/ai_guard/api/notice/<int:notice_id>/read", methods=["POST"])
@authed_only
def api_notice_read(notice_id):
    user = get_current_user()
    account = current_account()
    if account is None:
        abort(404)
    notice = AIGuardNotice.query.filter(
        AIGuardNotice.id == notice_id,
        detector.account_clause(AIGuardNotice, account.id),
    ).first_or_404()
    exists = AIGuardNoticeRead.query.filter_by(
        notice_id=notice.id, user_id=user.id
    ).first()
    if exists is None:
        db.session.add(AIGuardNoticeRead(notice_id=notice.id, user_id=user.id))
        db.session.commit()
    return jsonify({"success": True})
