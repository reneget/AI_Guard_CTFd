"""Add AI Guard wall of shame table

Revision ID: e7c1a4b2d9f0
Revises: d5b9f3a1c6e8
Create Date: 2026-10-21 22:00:00.000000

"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_all_tables

revision = "e7c1a4b2d9f0"
down_revision = "d5b9f3a1c6e8"
branch_labels = None
depends_on = None


def upgrade(op=None):
    if "aiguard_shames" in get_all_tables(op):
        return
    op.create_table(
        "aiguard_shames",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("admin_id", sa.Integer(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("date", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["admin_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id"),
        sa.UniqueConstraint("user_id"),
    )


def downgrade(op=None):
    op.drop_table("aiguard_shames")
