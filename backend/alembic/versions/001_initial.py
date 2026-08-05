"""Initial schema — create_all also used at startup for SQLite MVP."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Prefer SQLAlchemy create_all via init_db for SQLite MVP.
    # This revision documents the schema baseline for Postgres deploys.
    pass


def downgrade() -> None:
    pass
