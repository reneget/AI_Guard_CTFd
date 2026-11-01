import datetime
import json

from CTFd.models import db


def utcnow():
    return datetime.datetime.utcnow()


class AIGuardState(db.Model):
    """Current AI-risk state of a single account (team in teams mode, user in users mode)."""

    __tablename__ = "aiguard_states"
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), unique=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    score = db.Column(db.Float, nullable=False, default=0.0)
    whitelisted = db.Column(db.Boolean, nullable=False, default=False)
    # True when the account was hidden by this plugin (and not restored by an admin since)
    auto_hidden = db.Column(db.Boolean, nullable=False, default=False)
    hidden_at = db.Column(db.DateTime)
    # Date of the solve that triggered the last burst signal. Solves before it are not
    # counted again by the burst detector.
    last_burst_at = db.Column(db.DateTime)
    last_event_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=utcnow)


class AIGuardEvent(db.Model):
    """A single suspicious-activity record (or an admin action) for an account."""

    __tablename__ = "aiguard_events"
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # User that made the submission (in teams mode a member of team_id)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="SET NULL")
    )
    # Honeypot flag id (kept without a FK so the history survives flag deletion)
    flag_id = db.Column(db.Integer, index=True)
    kind = db.Column(db.String(32), nullable=False, index=True)
    weight = db.Column(db.Float, nullable=False, default=0.0)
    score_after = db.Column(db.Float, nullable=False, default=0.0)
    details = db.Column(db.Text)
    acknowledged = db.Column(db.Boolean, nullable=False, default=False, index=True)
    date = db.Column(db.DateTime, default=utcnow, index=True)

    actor = db.relationship("Users", foreign_keys=[actor_id], lazy="select")
    challenge = db.relationship(
        "Challenges", foreign_keys=[challenge_id], lazy="select"
    )

    @property
    def details_dict(self):
        try:
            return json.loads(self.details or "{}")
        except ValueError:
            return {}


class AIGuardView(db.Model):
    """The first time an account opened a challenge (used by the quick-solve signal)."""

    __tablename__ = "aiguard_views"
    __table_args__ = (
        db.UniqueConstraint("team_id", "challenge_id"),
        db.UniqueConstraint("user_id", "challenge_id"),
    )
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    # Member that opened the challenge first (in users mode the same as user_id)
    viewer_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), index=True
    )
    date = db.Column(db.DateTime, default=utcnow)

    viewer = db.relationship("Users", foreign_keys=[viewer_id], lazy="select")


class AIGuardShame(db.Model):
    """
    An account the organizers put on the wall of shame. Such an account is hidden from
    the scoreboard and can no longer submit flags.
    """

    __tablename__ = "aiguard_shames"
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), unique=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    # Public comment shown on the wall of shame
    comment = db.Column(db.Text)
    date = db.Column(db.DateTime, default=utcnow)

    admin = db.relationship("Users", foreign_keys=[admin_id], lazy="select")


class AIGuardNotice(db.Model):
    """A private message for an account, shown to its members by assets/notice.js."""

    __tablename__ = "aiguard_notices"
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    title = db.Column(db.Text)
    content = db.Column(db.Text)
    date = db.Column(db.DateTime, default=utcnow)


class AIGuardNoticeRead(db.Model):
    __tablename__ = "aiguard_notice_reads"
    __table_args__ = (db.UniqueConstraint("notice_id", "user_id"),)
    id = db.Column(db.Integer, primary_key=True)
    notice_id = db.Column(
        db.Integer, db.ForeignKey("aiguard_notices.id", ondelete="CASCADE")
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    date = db.Column(db.DateTime, default=utcnow)
