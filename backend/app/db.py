from sqlmodel import SQLModel, create_engine, Session
import os
from app.config import settings

# Ensure sqlite DB path directory exists
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite:///"):
    db_path = db_url.replace("sqlite:///", "")
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

connect_args = {"check_same_thread": False} if "sqlite" in db_url else {}
engine = create_engine(db_url, echo=settings.DEBUG, connect_args=connect_args)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
