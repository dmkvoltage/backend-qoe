from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import os
import logging
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import json
from typing import Optional

# Import your modules
from database import get_db, test_connection, get_connection_info, init_database
from models import User, NetworkLog, Feedback
from schemas import UserCreate, UserLogin, NetworkLogCreate, FeedbackCreate
from crud import (
    create_user, get_user_by_username, authenticate_user,
    create_network_log, create_feedback, get_network_logs, get_feedbacks
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="QoE App Backend",
    description="Backend API for Quality of Experience Mobile App",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
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
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Starting QoE App Backend...")
    init_database()
    logger.info("✅ Application startup complete")

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return username"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get current user from database"""
    user = get_user_by_username(db, username=username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

# Helper function to parse request body
async def parse_body(request: Request):
    """Parse request body as JSON"""
    try:
        body = await request.body()
        body_str = body.decode('utf-8')
        return json.loads(body_str)
    except Exception as e:
        logger.error(f"Error parsing request body: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "QoE App Backend API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "auth": ["/auth/register", "/auth/login"],
            "feedback": ["/feedback"],
            "network-logs": ["/network-logs"],
            "profile": ["/profile"],
            "recommendations": ["/recommendations/{location}"],
            "debug": ["/health", "/debug/echo"]
        }
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        db_status = test_connection()
        connection_info = get_connection_info()
        
        return {
            "status": "healthy" if db_status else "degraded",
            "database": {
                "connected": db_status,
                "type": connection_info.get("database_type", "unknown"),
                "url_preview": connection_info.get("working_url", "not available")
            },
            "timestamp": datetime.utcnow().isoformat(),
            "environment": os.getenv("RENDER_SERVICE_NAME", "local")
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

# Debug endpoint
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
            "headers": headers,
            "method": request.method,
            "url": str(request.url)
        }
    except Exception as e:
        return {"error": str(e)}

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/auth/register")
async def register(request: Request, db: Session = Depends(get_db)):
    """Register a new user"""
    try:
        data = await parse_body(request)
        
        # Validate required fields
        required_fields = ["username", "email", "password"]
        for field in required_fields:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Check if user already exists
        existing_user = get_user_by_username(db, username=data["username"])
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Create user
        user_create = UserCreate(**data)
        db_user = create_user(db=db, user=user_create)
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": db_user.username}, expires_delta=access_token_expires
        )
        
        logger.info(f"✅ User registered successfully: {data['username']}")
        return {
            "message": "User registered successfully",
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": db_user.id,
                "username": db_user.username,
                "email": db_user.email,
                "provider": db_user.provider
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Registration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/auth/login")
async def login(request: Request, db: Session = Depends(get_db)):
    """Login user"""
    try:
        data = await parse_body(request)
        
        # Validate required fields
        if "username" not in data or "password" not in data:
            raise HTTPException(status_code=400, detail="Username and password required")
        
        # Authenticate user
        user = authenticate_user(db, data["username"], data["password"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        logger.info(f"✅ User logged in successfully: {data['username']}")
        return {
            "message": "Login successful",
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "provider": user.provider
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Login failed: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

# ==================== PROTECTED ENDPOINTS ====================

@app.get("/profile")
async def get_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "provider": current_user.provider,
        "created_at": current_user.created_at,
        "is_active": current_user.is_active
    }

@app.post("/network-logs")
async def submit_network_log(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit a network log"""
    try:
        data = await parse_body(request)
        
        # Validate required fields
        required_fields = ["carrier", "location"]
        for field in required_fields:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Create network log
        log_create = NetworkLogCreate(**data)
        db_log = create_network_log(db=db, log=log_create, user_id=current_user.id)
        
        logger.info(f"✅ Network log submitted by user: {current_user.username}")
        return {
            "message": "Network log submitted successfully",
            "log_id": db_log.id,
            "timestamp": db_log.timestamp
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Network log submission failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit network log: {str(e)}")

@app.get("/network-logs")
async def get_user_network_logs(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's network logs"""
    try:
        logs = get_network_logs(db=db, user_id=current_user.id, skip=skip, limit=limit)
        return {
            "logs": logs,
            "count": len(logs),
            "user": current_user.username
        }
    except Exception as e:
        logger.error(f"❌ Failed to get network logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get network logs: {str(e)}")

@app.post("/feedback")
async def submit_feedback(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit feedback"""
    try:
        data = await parse_body(request)
        
        # Validate required fields
        required_fields = ["overall_satisfaction", "response_time", "usability", "carrier", "location"]
        for field in required_fields:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Create feedback
        feedback_create = FeedbackCreate(**data)
        db_feedback = create_feedback(db=db, feedback=feedback_create, user_id=current_user.id)
        
        logger.info(f"✅ Feedback submitted by user: {current_user.username}")
        return {
            "message": "Feedback submitted successfully",
            "feedback_id": db_feedback.id,
            "timestamp": db_feedback.timestamp
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Feedback submission failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@app.get("/feedback")
async def get_user_feedback(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's feedback"""
    try:
        feedbacks = get_feedbacks(db=db, user_id=current_user.id, skip=skip, limit=limit)
        return {
            "feedback": feedbacks,
            "count": len(feedbacks),
            "user": current_user.username
        }
    except Exception as e:
        logger.error(f"❌ Failed to get feedback: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get feedback: {str(e)}")

@app.get("/recommendations/{location}")
async def get_recommendations(
    location: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get provider recommendations for a location"""
    try:
        from crud import get_provider_recommendations
        recommendations = get_provider_recommendations(db=db, location=location)
        
        return {
            "location": location,
            "recommendations": recommendations,
            "count": len(recommendations),
            "user": current_user.username
        }
    except Exception as e:
        logger.error(f"❌ Failed to get recommendations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "path": str(request.url.path)
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
