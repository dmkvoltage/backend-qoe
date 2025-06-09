from fastapi import FastAPI, Depends, HTTPException, status, Request, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect
from datetime import datetime, timedelta
import os
import json
from typing import List, Optional, Dict, Any, Union
import uvicorn
from dotenv import load_dotenv

# JWT import with proper error handling
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    print("⚠️ JWT library not available")

# Load environment variables
load_dotenv()

# In-memory storage for when database is unavailable
users_memory = {}
feedback_memory = []
logs_memory = []

try:
    from database import get_db, engine, test_connection, get_connection_info
    from models import Base, User, Feedback, NetworkLog
    from schemas import (
        UserCreate, UserLogin, UserResponse, Token,
        FeedbackCreate, FeedbackResponse,
        NetworkLogCreate, NetworkLogResponse,
        RecommendationResponse
    )
    from crud import (
        create_user, authenticate_user, get_user_by_username,
        create_feedback, get_feedbacks, create_network_log,
        get_network_logs, get_provider_recommendations
    )
    DATABASE_AVAILABLE = test_connection()
    print(f"✅ Database modules imported. Connection: {'✅' if DATABASE_AVAILABLE else '❌'}")
except Exception as e:
    print(f"⚠️ Database modules not available: {e}")
    DATABASE_AVAILABLE = False
    
    # Define basic models if schemas not available
    from pydantic import BaseModel, EmailStr
    
    class UserCreate(BaseModel):
        username: str
        email: str
        password: str
        provider: Optional[str] = None
    
    class UserLogin(BaseModel):
        username: str
        password: str
    
    class UserResponse(BaseModel):
        id: int
        username: str
        email: str
        provider: Optional[str] = None
        created_at: datetime
        is_active: bool
    
    class Token(BaseModel):
        access_token: str
        token_type: str

app = FastAPI(
    title="QoE Boost API",
    description="Quality of Experience monitoring and feedback API with Supabase",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)  # Changed to auto_error=False to make it optional

# Import passlib with error handling
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False
    print("⚠️ Passlib not available, using simple password hashing")

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    """Create JWT access token with proper error handling"""
    if not JWT_AVAILABLE:
        # Fallback: create a simple token
        import base64
        token_data = json.dumps({**data, "exp": (datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).isoformat()})
        return base64.b64encode(token_data.encode()).decode()
    
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"JWT encoding error: {e}")
        # Fallback to simple token
        import base64
        token_data = json.dumps({**data, "exp": (datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).isoformat()})
        return base64.b64encode(token_data.encode()).decode()

def verify_password(plain_password, hashed_password):
    """Verify password with fallback"""
    if PASSLIB_AVAILABLE:
        return pwd_context.verify(plain_password, hashed_password)
    else:
        # Simple comparison for fallback
        return plain_password == hashed_password

def get_password_hash(password):
    """Hash password with fallback"""
    if PASSLIB_AVAILABLE:
        return pwd_context.hash(password)
    else:
        # Simple storage for fallback (not secure, just for testing)
        return password

# Database checker functions integrated into FastAPI
def check_environment_variables():
    """Check if all required environment variables are set"""
    env_vars = [
        "SUPABASE_DATABASE_URL",
        "DATABASE_URL",
        "SECRET_KEY"
    ]
    
    found_vars = {}
    for var in env_vars:
        value = os.getenv(var)
        if value:
            # Mask sensitive parts of the URL
            if "postgresql://" in value:
                masked = value[:20] + "***" + value[-20:] if len(value) > 40 else "***"
                found_vars[var] = masked
            else:
                found_vars[var] = value[:10] + "***" if len(value) > 10 else "***"
        else:
            found_vars[var] = "❌ NOT SET"
    
    return found_vars

def test_direct_connection():
    """Test direct connection using psycopg2"""
    try:
        import psycopg2
        
        # Your confirmed connection details
        connection_params = {
            "host": "aws-0-sa-east-1.pooler.supabase.com",
            "port": 6543,
            "database": "postgres",
            "user": "postgres.tlcbimopgpcaxgehncey",
            "password": "08200108dyekrane"
        }
        
        conn = psycopg2.connect(**connection_params)
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        
        # Test permissions
        cursor.execute("SELECT current_user, current_database();")
        user, db = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return {
            "success": True,
            "version": version,
            "current_user": user,
            "current_database": db
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def check_tables_info():
    """Check table information"""
    try:
        if not DATABASE_AVAILABLE:
            return {"error": "Database not available"}
            
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        table_info = {
            "tables": existing_tables,
            "table_counts": {},
            "required_tables": ["users", "feedback", "network_logs"],
            "missing_tables": []
        }
        
        # Check for required tables
        required_tables = ["users", "feedback", "network_logs"]
        table_info["missing_tables"] = [table for table in required_tables if table not in existing_tables]
        
        # Get row counts
        with engine.connect() as conn:
            for table in existing_tables:
                try:
                    result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                    count = result.fetchone()[0]
                    table_info["table_counts"][table] = count
                except Exception as e:
                    table_info["table_counts"][table] = f"Error: {str(e)}"
        
        return table_info
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
async def root():
    return {
        "message": "QoE Boost API is running!",
        "version": "1.0.0",
        "database": "Connected" if DATABASE_AVAILABLE else "In-Memory Mode",
        "jwt": "Available" if JWT_AVAILABLE else "Fallback Mode",
        "passlib": "Available" if PASSLIB_AVAILABLE else "Fallback Mode",
        "endpoints": {
            "auth": ["/auth/register", "/auth/login"],
            "feedback": ["/feedback"],
            "network-logs": ["/network-logs"],
            "debug": ["/health", "/debug/routes", "/debug/echo", "/debug/database", "/debug/database-check"]
        }
    }

@app.get("/debug/database-check")
async def comprehensive_database_check():
    """Comprehensive database connection and health check"""
    try:
        check_result = {
            "timestamp": datetime.utcnow(),
            "environment_variables": check_environment_variables(),
            "direct_connection": test_direct_connection(),
            "database_available": DATABASE_AVAILABLE,
            "sqlalchemy_connection": False,
            "tables_info": {},
            "recent_data": {},
            "test_operations": {},
            "summary": {}
        }
        
        # Test SQLAlchemy connection
        if DATABASE_AVAILABLE:
            try:
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT 1 as test"))
                    test_value = result.fetchone()[0]
                    check_result["sqlalchemy_connection"] = True
                    
                    # Get database info
                    result = conn.execute(text("SELECT current_database(), current_user, version()"))
                    db_name, user, version = result.fetchone()
                    check_result["database_info"] = {
                        "database": db_name,
                        "user": user,
                        "version": version[:100] + "..." if len(version) > 100 else version
                    }
                    
            except Exception as e:
                check_result["sqlalchemy_error"] = str(e)
        
        # Get table information
        check_result["tables_info"] = check_tables_info()
        
        # Get recent data samples
        if DATABASE_AVAILABLE and check_result["sqlalchemy_connection"]:
            try:
                with engine.connect() as conn:
                    # Check network_logs
                    try:
                        result = conn.execute(text(
                            "SELECT id, carrier, network_type, download_speed, timestamp "
                            "FROM network_logs ORDER BY timestamp DESC LIMIT 5"
                        ))
                        check_result["recent_data"]["network_logs"] = [
                            {
                                "id": row[0],
                                "carrier": row[1],
                                "network_type": row[2],
                                "download_speed": float(row[3]) if row[3] else 0,
                                "timestamp": row[4].isoformat() if row[4] else None
                            }
                            for row in result.fetchall()
                        ]
                    except Exception as e:
                        check_result["recent_data"]["network_logs_error"] = str(e)
                    
                    # Check feedback
                    try:
                        result = conn.execute(text(
                            "SELECT id, overall_satisfaction, comments, timestamp "
                            "FROM feedback ORDER BY timestamp DESC LIMIT 5"
                        ))
                        check_result["recent_data"]["feedback"] = [
                            {
                                "id": row[0],
                                "overall_satisfaction": row[1],
                                "comments": row[2],
                                "timestamp": row[3].isoformat() if row[3] else None
                            }
                            for row in result.fetchall()
                        ]
                    except Exception as e:
                        check_result["recent_data"]["feedback_error"] = str(e)
                        
                    # Test data operations
                    try:
                        # Test INSERT
                        insert_query = text("""
                            INSERT INTO network_logs (
                                user_id, carrier, network_type, signal_strength, 
                                download_speed, upload_speed, latency, location
                            ) VALUES (
                                1, 'TEST_CHECKER', 'TEST_TYPE', -50, 
                                10.5, 5.2, 20, 'TEST_LOCATION'
                            ) RETURNING id
                        """)
                        
                        result = conn.execute(insert_query)
                        new_id = result.fetchone()[0]
                        
                        # Test SELECT
                        select_query = text("SELECT * FROM network_logs WHERE id = :id")
                        result = conn.execute(select_query, {"id": new_id})
                        record = result.fetchone()
                        
                        # Test DELETE (cleanup)
                        delete_query = text("DELETE FROM network_logs WHERE id = :id")
                        conn.execute(delete_query, {"id": new_id})
                        conn.commit()
                        
                        check_result["test_operations"] = {
                            "insert": "✅ SUCCESS",
                            "select": "✅ SUCCESS",
                            "delete": "✅ SUCCESS",
                            "test_record_id": new_id
                        }
                        
                    except Exception as e:
                        check_result["test_operations"] = {
                            "error": str(e),
                            "status": "❌ FAILED"
                        }
                        
            except Exception as e:
                check_result["data_operations_error"] = str(e)
        
        # Generate summary
        summary = {
            "overall_status": "🎉 FULLY FUNCTIONAL",
            "issues": []
        }
        
        if not check_result["direct_connection"]["success"]:
            summary["issues"].append("Direct connection failed")
            summary["overall_status"] = "❌ CONNECTION ISSUES"
        
        if not check_result["sqlalchemy_connection"]:
            summary["issues"].append("SQLAlchemy connection failed")
            summary["overall_status"] = "❌ CONNECTION ISSUES"
        
        if check_result["tables_info"].get("missing_tables"):
            summary["issues"].append(f"Missing tables: {check_result['tables_info']['missing_tables']}")
            summary["overall_status"] = "⚠️ MISSING TABLES"
        
        if check_result["test_operations"].get("error"):
            summary["issues"].append("Data operations failed")
            summary["overall_status"] = "⚠️ OPERATION ISSUES"
        
        check_result["summary"] = summary
        
        return check_result
        
    except Exception as e:
        return {
            "error": f"Database check failed: {str(e)}",
            "timestamp": datetime.utcnow()
        }

@app.get("/health")
async def health_check():
    try:
        connection_info = get_connection_info() if DATABASE_AVAILABLE else None
        return {
            "status": "healthy",
            "database": "connected" if DATABASE_AVAILABLE else "in-memory mode",
            "jwt": "available" if JWT_AVAILABLE else "fallback mode",
            "passlib": "available" if PASSLIB_AVAILABLE else "fallback mode",
            "connection_info": connection_info,
            "timestamp": datetime.utcnow(),
            "memory_stats": {
                "users": len(users_memory),
                "feedback": len(feedback_memory),
                "logs": len(logs_memory)
            }
        }
    except Exception as e:
        return {
            "status": "degraded",
            "database": "error",
            "error": str(e),
            "timestamp": datetime.utcnow()
        }

@app.get("/debug/database")
async def debug_database():
    """Comprehensive database debug information"""
    try:
        debug_info = {
            "timestamp": datetime.utcnow(),
            "database_available": DATABASE_AVAILABLE,
            "connection_test": False,
            "tables": [],
            "table_counts": {},
            "recent_data": {},
            "errors": []
        }
        
        if DATABASE_AVAILABLE:
            try:
                # Test connection
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                    debug_info["connection_test"] = True
                    
                    # Get table information
                    inspector = inspect(engine)
                    debug_info["tables"] = inspector.get_table_names()
                    
                    # Get row counts for each table
                    for table in debug_info["tables"]:
                        try:
                            result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                            count = result.fetchone()[0]
                            debug_info["table_counts"][table] = count
                        except Exception as e:
                            debug_info["table_counts"][table] = f"Error: {str(e)}"
                    
                    # Get recent data samples
                    if "network_logs" in debug_info["tables"]:
                        try:
                            result = conn.execute(text(
                                "SELECT id, carrier, network_type, download_speed, timestamp "
                                "FROM network_logs ORDER BY timestamp DESC LIMIT 5"
                            ))
                            debug_info["recent_data"]["network_logs"] = [
                                {
                                    "id": row[0],
                                    "carrier": row[1],
                                    "network_type": row[2],
                                    "download_speed": float(row[3]) if row[3] else 0,
                                    "timestamp": row[4].isoformat() if row[4] else None
                                }
                                for row in result.fetchall()
                            ]
                        except Exception as e:
                            debug_info["errors"].append(f"Error fetching network_logs: {str(e)}")
                    
                    if "feedback" in debug_info["tables"]:
                        try:
                            result = conn.execute(text(
                                "SELECT id, overall_satisfaction, comments, timestamp "
                                "FROM feedback ORDER BY timestamp DESC LIMIT 5"
                            ))
                            debug_info["recent_data"]["feedback"] = [
                                {
                                    "id": row[0],
                                    "overall_satisfaction": row[1],
                                    "comments": row[2],
                                    "timestamp": row[3].isoformat() if row[3] else None
                                }
                                for row in result.fetchall()
                            ]
                        except Exception as e:
                            debug_info["errors"].append(f"Error fetching feedback: {str(e)}")
                            
            except Exception as e:
                debug_info["errors"].append(f"Database connection error: {str(e)}")
        else:
            debug_info["errors"].append("Database not available - using in-memory storage")
            debug_info["memory_data"] = {
                "users": len(users_memory),
                "feedback": len(feedback_memory),
                "logs": len(logs_memory),
                "recent_feedback": feedback_memory[-5:] if feedback_memory else [],
                "recent_logs": logs_memory[-5:] if logs_memory else []
            }
        
        return debug_info
        
    except Exception as e:
        return {
            "error": f"Debug endpoint error: {str(e)}",
            "timestamp": datetime.utcnow()
        }

@app.get("/debug/routes")
async def list_routes():
    routes = []
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            routes.append({
                "path": route.path,
                "methods": list(route.methods)
            })
    return {"routes": routes}

# Helper function to parse request body
async def parse_body(request: Request) -> Dict[str, Any]:
    """Parse request body as JSON, handling both raw string and JSON object"""
    try:
        body = await request.body()
        body_str = body.decode('utf-8')
        print(f"Raw request body: {body_str}")
        return json.loads(body_str)
    except Exception as e:
        print(f"Error parsing request body: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

# Authentication endpoints with fallback to in-memory storage
@app.post("/auth/register")
async def register(request: Request):
    try:
        data = await parse_body(request)
        user = UserCreate(**data)
        
        if DATABASE_AVAILABLE:
            try:
                db = next(get_db())
                # Check if user already exists
                db_user = get_user_by_username(db, username=user.username)
                if db_user:
                    raise HTTPException(status_code=400, detail="Username already registered")
                
                # Create new user
                new_user = create_user(db=db, user=user)
                db.close()
                return new_user
            except Exception as db_error:
                print(f"Database error, falling back to memory: {db_error}")
                # Fall through to memory storage
        
        # In-memory storage fallback
        if user.username in users_memory:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        user_id = len(users_memory) + 1
        hashed_password = get_password_hash(user.password)
        
        users_memory[user.username] = {
            "id": user_id,
            "username": user.username,
            "email": user.email,
            "password": hashed_password,
            "provider": user.provider,
            "created_at": datetime.utcnow(),
            "is_active": True
        }
        
        return {
            "id": user_id,
            "username": user.username,
            "email": user.email,
            "provider": user.provider,
            "created_at": users_memory[user.username]["created_at"],
            "is_active": True,
            "storage": "memory"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/auth/login")
async def login(request: Request):
    try:
        data = await parse_body(request)
        user = UserLogin(**data)
        
        if DATABASE_AVAILABLE:
            try:
                db = next(get_db())
                db_user = authenticate_user(db, user.username, user.password)
                if db_user:
                    access_token = create_access_token(data={"sub": db_user.username})
                    db.close()
                    return {"access_token": access_token, "token_type": "bearer", "storage": "database"}
                db.close()
            except Exception as db_error:
                print(f"Database error, falling back to memory: {db_error}")
                # Fall through to memory storage
        
        # In-memory storage fallback
        if user.username not in users_memory:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        stored_user = users_memory[user.username]
        if not verify_password(user.password, stored_user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        access_token = create_access_token(data={"sub": user.username})
        return {"access_token": access_token, "token_type": "bearer", "storage": "memory"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

# Debug endpoint to echo request body
@app.post("/debug/echo")
async def echo_request(request: Request):
    """Echo the request body for debugging"""
    try:
        body = await request.body()
        body_str = body.decode('utf-8')
        headers = dict(request.headers)
        
        parsed_json = None
        try:
            parsed_json = json.loads(body_str)
        except:
            parsed_json = "Not valid JSON"
        
        return {
            "raw_body": body_str,
            "content_type": headers.get("content-type"),
            "parsed_json": parsed_json,
            "headers": headers
        }
    except Exception as e:
        return {"error": str(e)}

# FIXED - Now saves to database when available
@app.post("/feedback")
async def submit_feedback(request: Request):
    try:
        data = await parse_body(request)
        
        # Try to save to database first
        if DATABASE_AVAILABLE:
            try:
                db = next(get_db())
                
                # Create feedback object for database
                feedback_data = {
                    "overall_satisfaction": data.get("overall_satisfaction", 3),
                    "response_time": data.get("response_time", 3),
                    "usability": data.get("usability", 3),
                    "comments": data.get("comments", ""),
                    "issue_type": data.get("issue_type", "general"),
                    "carrier": data.get("carrier", "Unknown"),
                    "network_type": data.get("network_type", "Unknown"),
                    "location": data.get("location", "Unknown"),
                    "signal_strength": data.get("signal_strength", -100),
                    "download_speed": data.get("download_speed", 0.0),
                    "upload_speed": data.get("upload_speed", 0.0),
                    "latency": data.get("latency", 999),
                }
                
                # Print detailed debug info
                print(f"📝 Attempting to save feedback with data: {feedback_data}")
                
                # Create feedback in database (without user_id for anonymous)
                db_feedback = Feedback(
                    user_id=1,  # Use anonymous user ID
                    **feedback_data
                )
                db.add(db_feedback)
                db.commit()
                db.refresh(db_feedback)
                
                print(f"✅ Feedback saved to database: {db_feedback.id}")
                
                db.close()
                return {
                    "id": db_feedback.id,
                    "timestamp": db_feedback.timestamp,
                    "storage": "database",
                    **feedback_data
                }
                
            except Exception as db_error:
                print(f"❌ Database error saving feedback: {db_error}")
                print(f"❌ Feedback data that failed: {data}")
                # Fall through to memory storage
        
        # Fallback to in-memory storage
        feedback_id = len(feedback_memory) + 1
        feedback = {
            "id": feedback_id,
            "timestamp": datetime.utcnow(),
            "storage": "memory",
            "anonymous": True,
            **data
        }
        feedback_memory.append(feedback)
        print(f"✅ Anonymous feedback submitted to memory: {feedback_id}")
        return feedback
        
    except Exception as e:
        print(f"Feedback error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@app.get("/feedback")
async def get_user_feedback():
    return feedback_memory

# FIXED - Now saves to database when available
@app.post("/network-logs")
async def submit_network_log(request: Request):
    try:
        data = await parse_body(request)
        
        # Try to save to database first
        if DATABASE_AVAILABLE:
            try:
                db = next(get_db())
                
                # Create network log object for database
                log_data = {
                    "carrier": data.get("carrier", "Unknown"),
                    "network_type": data.get("network_type", "Unknown"),
                    "signal_strength": data.get("signal_strength", -100),
                    "download_speed": data.get("download_speed", 0.0),
                    "upload_speed": data.get("upload_speed", 0.0),
                    "latency": data.get("latency", 999),
                    "jitter": data.get("jitter", 0.0),
                    "packet_loss": data.get("packet_loss", 0.0),
                    "location": data.get("location", "Unknown"),
                    "device_info": data.get("device_info", "Unknown"),
                    "app_version": data.get("app_version", "1.0.0"),
                }
                
                # Create network log in database (without user_id for anonymous)
                db_log = NetworkLog(
                    user_id=1,  # Use anonymous user ID
                    **log_data
                )
                db.add(db_log)
                db.commit()
                db.refresh(db_log)
                db.close()
                
                print(f"✅ Network log saved to database: {db_log.id}")
                return {
                    "id": db_log.id,
                    "timestamp": db_log.timestamp,
                    "storage": "database",
                    **log_data
                }
                
            except Exception as db_error:
                print(f"Database error, falling back to memory: {db_error}")
                # Fall through to memory storage
        
        # Fallback to in-memory storage
        log_id = len(logs_memory) + 1
        log = {
            "id": log_id,
            "timestamp": datetime.utcnow(),
            "storage": "memory",
            "anonymous": True,
            **data
        }
        logs_memory.append(log)
        print(f"✅ Anonymous network log submitted to memory: {log_id}")
        return log
        
    except Exception as e:
        print(f"Network log error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit network log: {str(e)}")

@app.get("/network-logs")
async def get_user_network_logs():
    return logs_memory

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
