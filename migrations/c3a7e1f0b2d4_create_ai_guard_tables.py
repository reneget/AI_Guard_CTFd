"""Create AI Guard tables

Revision ID: c3a7e1f0b2d4
Revises:
Create Date: 2026-10-21 12:00:00.000000

"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_all_tables

revision = "c3a7e1f0b2d4"
down_revision = None
branch_labels = None
depends_on = None


def upgrade(op=None):
    tables = get_all_tables(op)

    if "aiguard_states" not in tables:
        op.create_table(
            "aiguard_states",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("team_id", sa.Integer(), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("score", sa.Float(), nullable=False),
            sa.Column("whitelisted", sa.Boolean(), nullable=False),
            sa.Column("auto_hidden", sa.Boolean(), nullable=False),
            sa.Column("hidden_at", sa.DateTime(), nullable=True),
            sa.Column("last_burst_at", sa.DateTime(), nullable=True),
            sa.Column("last_event_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("team_id"),
            sa.UniqueConstraint("user_id"),
        )

    if "aiguard_events" not in tables:
        op.create_table(
            "aiguard_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("team_id", sa.Integer(), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("actor_id", sa.Integer(), nullable=True),
            sa.Column("challenge_id", sa.Integer(), nullable=True),
            sa.Column("flag_id", sa.Integer(), nullable=True),
            sa.Column("kind", sa.String(length=32), nullable=False),
            sa.Column("weight", sa.Float(), nullable=False),
            sa.Column("score_after", sa.Float(), nullable=False),
            sa.Column("details", sa.Text(), nullable=True),
            sa.Column("acknowledged", sa.Boolean(), nullable=False),
            sa.Column("date", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(
                ["challenge_id"], ["challenges.id"], ondelete="SET NULL"
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        for column in ("team_id", "user_id", "flag_id", "kind", "acknowledged", "date"):
            op.create_index(f"ix_aiguard_events_{column}", "aiguard_events", [column])

    if "aiguard_notices" not in tables:
        op.create_table(
            "aiguard_notices",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("team_id", sa.Integer(), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("title", sa.Text(), nullable=True),
            sa.Column("content", sa.Text(), nullable=True),
            sa.Column("date", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_aiguard_notices_team_id", "aiguard_notices", ["team_id"])
        op.create_index("ix_aiguard_notices_user_id", "aiguard_notices", ["user_id"])

    if "aiguard_notice_reads" not in tables:
        op.create_table(
            "aiguard_notice_reads",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("notice_id", sa.Integer(), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("date", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(
                ["notice_id"], ["aiguard_notices.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("notice_id", "user_id"),
        )


def downgrade(op=None):
    op.drop_table("aiguard_notice_reads")
    op.drop_table("aiguard_notices")
    op.drop_table("aiguard_events")
    op.drop_table("aiguard_states")
