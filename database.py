import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Configure the backend service with the "
        "Render PostgreSQL internal connection string."
    )

# Render and some PostgreSQL providers may expose postgres:// URLs. SQLAlchemy
# expects postgresql:// for the psycopg2 driver.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def print_db_info():
    safe_database_url = DATABASE_URL
    if "@" in safe_database_url:
        safe_database_url = f"***@{safe_database_url.split('@', 1)[1]}"

    print("=" * 70)
    print(" MINI EDR DATABASE INFO ")
    print("=" * 70)
    print("DATABASE_URL:", safe_database_url)
    print("=" * 70)
