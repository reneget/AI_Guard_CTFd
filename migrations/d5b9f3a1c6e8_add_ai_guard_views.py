"""Add AI Guard challenge views table

Revision ID: d5b9f3a1c6e8
Revises: c3a7e1f0b2d4
Create Date: 2026-10-21 20:00:00.000000

"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_all_tables

revision = "d5b9f3a1c6e8"
down_revision = "c3a7e1f0b2d4"
branch_labels = None
depends_on = None


def upgrade(op=None):
    if "aiguard_views" in get_all_tables(op):
        return
    op.create_table(
        "aiguard_views",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("viewer_id", sa.Integer(), nullable=True),
        sa.Column("challenge_id", sa.Integer(), nullable=True),
        sa.Column("date", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["viewer_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["challenge_id"], ["challenges.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id", "challenge_id"),
        sa.UniqueConstraint("user_id", "challenge_id"),
    )
    op.create_index("ix_aiguard_views_challenge_id", "aiguard_views", ["challenge_id"])


def downgrade(op=None):
    op.drop_table("aiguard_views")
