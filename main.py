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
            "debug": ["/health", "/debug/routes", "/debug/echo"]
        }
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

# REMOVED AUTHENTICATION REQUIREMENT - Now accepts anonymous submissions
@app.post("/feedback")
async def submit_feedback(request: Request):
    try:
        data = await parse_body(request)
        feedback_id = len(feedback_memory) + 1
        feedback = {
            "id": feedback_id,
            "timestamp": datetime.utcnow(),
            "storage": "memory",
            "anonymous": True,  # Mark as anonymous submission
            **data
        }
        feedback_memory.append(feedback)
        print(f"✅ Anonymous feedback submitted: {feedback_id}")
        return feedback
    except Exception as e:
        print(f"Feedback error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@app.get("/feedback")
async def get_user_feedback():
    return feedback_memory

# REMOVED AUTHENTICATION REQUIREMENT - Now accepts anonymous submissions
@app.post("/network-logs")
async def submit_network_log(request: Request):
    try:
        data = await parse_body(request)
        log_id = len(logs_memory) + 1
        log = {
            "id": log_id,
            "timestamp": datetime.utcnow(),
            "storage": "memory",
            "anonymous": True,  # Mark as anonymous submission
            **data
        }
        logs_memory.append(log)
        print(f"✅ Anonymous network log submitted: {log_id}")
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
