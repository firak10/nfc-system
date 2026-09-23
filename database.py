import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# String de conexão fornecida pelo Supabase
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:[yMEl1uYhF2mcgMvy]@db.wroxsecuaftajtsbnctu.supabase.co:5432/postgres"
)

# Render / Supabase requerem protocolo postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()