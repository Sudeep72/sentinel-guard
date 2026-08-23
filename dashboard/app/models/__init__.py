"""SQLAlchemy ORM models.

Importing this package (as app/db/migrations/env.py does) registers
every model against ``Base.metadata``, which is what makes Alembic
autogenerate see the full schema.
"""

from app.models.baseline import Baseline
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.score import CategoryScoreRecord, SecurityScoreRecord
from app.models.server import Server
from app.models.user import User

__all__ = [
    "Baseline",
    "Finding",
    "Scan",
    "CategoryScoreRecord",
    "SecurityScoreRecord",
    "Server",
    "User",
]
