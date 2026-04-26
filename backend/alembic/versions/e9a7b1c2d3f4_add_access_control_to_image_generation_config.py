"""add_access_control_to_image_generation_config

Revision ID: e9a7b1c2d3f4
Revises: ffc707a226b4
Create Date: 2026-04-26 09:45:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "e9a7b1c2d3f4"
down_revision = "a7c3e2b1d4f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add access control columns to image_generation_config table
    op.add_column(
        "image_generation_config",
        sa.Column(
            "is_public",
            sa.Boolean(),
            nullable=False,
            server_default="true"
        )
    )
    op.add_column(
        "image_generation_config",
        sa.Column(
            "groups",
            postgresql.ARRAY(sa.Integer()),
            nullable=False,
            server_default="{}"
        )
    )
    op.add_column(
        "image_generation_config",
        sa.Column(
            "personas",
            postgresql.ARRAY(sa.Integer()),
            nullable=False,
            server_default="{}"
        )
    )


def downgrade() -> None:
    # Remove access control columns from image_generation_config table
    op.drop_column("image_generation_config", "personas")
    op.drop_column("image_generation_config", "groups")
    op.drop_column("image_generation_config", "is_public")
