from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv
import time
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
try:
    load_dotenv()
except ImportError:
    pass

# Database connection strings
DATABASE_URLS = [
    os.getenv("DATABASE_URL"),  # Render's database URL
    os.getenv("SUPABASE_DATABASE_URL"),
    # Fallback connection string
    "postgresql://postgres.tlcbimopgpcaxgehncey:08200108dyekrane@aws-0-sa-east-1.pooler.supabase.com:6543/postgres",
]

# Filter out None values
DATABASE_URLS = [url for url in DATABASE_URLS if url]

logger.info(f"🔗 Trying {len(DATABASE_URLS)} connection strings...")

# Connection setup
engine = None
working_url = None
max_retries = 3
retry_delay = 2

for i, url in enumerate(DATABASE_URLS):
    retries = 0
    while retries < max_retries:
        try:
            logger.info(f"Trying connection {i+1} (attempt {retries+1})")
            
            test_engine = create_engine(
                url,
                pool_pre_ping=True,
                pool_recycle=300,
                pool_size=5,
                max_overflow=10,
                echo=False,
                connect_args={
                    "connect_timeout": 10,
                    "keepalives": 1,
                    "keepalives_idle": 30,
                    "keepalives_interval": 10,
                    "keepalives_count": 5
                }
            )
            
            # Test connection
            with test_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            engine = test_engine
            working_url = url
            logger.info(f"✅ Connection successful with URL {i+1}")
            break
            
        except Exception as e:
            logger.error(f"❌ Connection {i+1} attempt {retries+1} failed: {e}")
            retries += 1
            if retries < max_retries:
                time.sleep(retry_delay)
    
    if engine is not None:
        break

if engine is None:
    logger.error("❌ All database connections failed. Creating fallback SQLite database.")
    engine = create_engine("sqlite:///./fallback.db", echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_connection():
    """Test the database connection"""
    if engine is None:
        return False
    
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            logger.info("✅ Database connection test successful")
            return True
    except Exception as e:
        logger.error(f"❌ Database connection test failed: {e}")
        return False

def get_connection_info():
    """Get information about the current database connection"""
    return {
        "working_url": working_url[:50] + "..." if working_url else None,
        "engine_available": engine is not None,
        "connection_test": test_connection(),
        "database_type": "postgresql" if working_url and "postgresql" in working_url else "sqlite"
    }

def init_database():
    """Initialize database tables"""
    try:
        from models import Base
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database tables: {e}")
