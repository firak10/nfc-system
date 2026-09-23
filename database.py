import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("A variável de ambiente DATABASE_URL não foi encontrada!")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if "sslmode" not in DATABASE_URL:
    DATABASE_URL += "?sslmode=require" if "?" not in DATABASE_URL else "&sslmode=require"

# connect_args com prepare_threshold=None é ideal para o Transaction Pooler do Supabase (porta 6543)
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"prepare_threshold": None} if ":6543" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
