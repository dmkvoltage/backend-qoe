from fastapi import FastAPI, HTTPException, Depends, status, Request, Body, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import os
import logging
from datetime import datetime, timedelta
import jwt
from typing import List, Dict, Any, Optional
import json

# Import your modules
from database import get_db, test_connection, get_connection_info, init_database
from models import User, NetworkLog, Feedback
from schemas import (
    UserCreate, UserLogin, UserResponse, Token,
    NetworkLogCreate, NetworkLogResponse,
    FeedbackCreate, FeedbackResponse,
    RecommendationResponse
)
from crud import (
    create_user, get_user_by_email, get_user_by_username,
    create_network_log, create_feedback, get_network_logs, get_feedbacks,
    get_password_hash, verify_password, authenticate_user,
    get_provider_recommendations
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="QoE App Backend API",
    description="Backend API for Quality of Experience Mobile App - Network monitoring and feedback collection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware - Configure properly for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this with your Flutter app domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Starting QoE App Backend...")
    init_database()
    logger.info("✅ Application startup complete")

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "QoE App Backend API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "timestamp": datetime.utcnow().isoformat()
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    try:
        db_status = test_connection()
        connection_info = get_connection_info()
        
        return {
            "status": "healthy" if db_status else "degraded",
            "database": {
                "connected": db_status,
                "type": connection_info.get("database_type", "unknown")
            },
            "timestamp": datetime.utcnow().isoformat(),
            "environment": os.getenv("RENDER_SERVICE_NAME", "local"),
            "version": "1.0.0"
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

# Utility functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(current_user_email: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = get_user_by_email(db, current_user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Authentication endpoints
@app.post("/auth/register", tags=["Authentication"])
async def register(request: Request, db: Session = Depends(get_db)):
    try:
        # Log request details for debugging
        content_type = request.headers.get("content-type", "")
        logger.info(f"Register request - Content-Type: {content_type}")
        
        # Read raw body
        body = await request.body()
        body_str = body.decode('utf-8')
        logger.info(f"Raw request body: {body_str}")
        
        # Parse JSON manually
        try:
            data = json.loads(body_str)
            username = data.get("username")
            email = data.get("email")
            password = data.get("password")
            provider = data.get("provider")
            
            if not username or not email or not password:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Missing required fields: username, email, password"}
                )
            
            # Check if user already exists
            if get_user_by_email(db, email):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Email already registered"}
                )
            
            if get_user_by_username(db, username):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Username already taken"}
                )
            
            # Hash password and create user
            hashed_password = get_password_hash(password)
            user_data = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "provider": provider
            }
            
            db_user = create_user(db, user_data)
            
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": db_user.email}, expires_delta=access_token_expires
            )
            
            logger.info(f"✅ User registered successfully: {email}")
            return JSONResponse(content={
                "message": "User registered successfully",
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": db_user.id,
                    "email": db_user.email,
                    "username": db_user.username,
                    "provider": db_user.provider
                }
            })
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return JSONResponse(
                status_code=400,
                content={"detail": f"Invalid JSON format: {str(e)}"}
            )
    except Exception as e:
        logger.error(f"❌ Registration failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Registration failed: {str(e)}"}
        )

# Raw login endpoint that handles the request manually
@app.post("/auth/login", tags=["Authentication"])
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        # Log request details for debugging
        content_type = request.headers.get("content-type", "")
        logger.info(f"Login request - Content-Type: {content_type}")
        
        # Read raw body
        body = await request.body()
        body_str = body.decode('utf-8')
        logger.info(f"Raw request body: {body_str}")
        
        # Parse JSON manually
        try:
            data = json.loads(body_str)
            username = data.get("username")
            password = data.get("password")
            
            if not username or not password:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Missing username or password"}
                )
                
            # Authenticate user
            db_user = authenticate_user(db, username, password)
            if not db_user:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid credentials"}
                )
            
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": db_user.email}, expires_delta=access_token_expires
            )
            
            logger.info(f"✅ User logged in successfully: {db_user.email}")
            return JSONResponse(content={
                "message": "Login successful",
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": db_user.id,
                    "email": db_user.email,
                    "username": db_user.username,
                    "provider": db_user.provider
                }
            })
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return JSONResponse(
                status_code=400,
                content={"detail": f"Invalid JSON format: {str(e)}"}
            )
    except Exception as e:
        logger.error(f"❌ Login failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Login failed: {str(e)}"}
        )

# Network logs endpoints
@app.post("/network-logs", tags=["Network Logs"])
async def submit_network_log(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Read raw body
        body = await request.body()
        body_str = body.decode('utf-8')
        
        # Parse JSON manually
        data = json.loads(body_str)
        data["user_id"] = current_user.id
        
        db_log = create_network_log(db, data)
        
        logger.info(f"✅ Network log submitted by user: {current_user.email}")
        return JSONResponse(content={
            "message": "Network log submitted successfully",
            "log_id": db_log.id,
            "timestamp": db_log.timestamp.isoformat()
        })
    except json.JSONDecodeError as e:
        return JSONResponse(
            status_code=400,
            content={"detail": f"Invalid JSON format: {str(e)}"}
        )
    except Exception as e:
        logger.error(f"❌ Network log submission failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to submit network log"}
        )

@app.get("/network-logs", tags=["Network Logs"])
async def get_user_network_logs(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        logs = get_network_logs(db, user_id=current_user.id, skip=skip, limit=limit)
        
        # Convert to JSON serializable format
        logs_data = []
        for log in logs:
            log_dict = {
                "id": log.id,
                "user_id": log.user_id,
                "carrier": log.carrier,
                "network_type": log.network_type,
                "signal_strength": log.signal_strength,
                "download_speed": log.download_speed,
                "upload_speed": log.upload_speed,
                "latency": log.latency,
                "jitter": log.jitter,
                "packet_loss": log.packet_loss,
                "location": log.location,
                "device_info": log.device_info,
                "app_version": log.app_version,
                "timestamp": log.timestamp.isoformat()
            }
            logs_data.append(log_dict)
        
        return JSONResponse(content=logs_data)
    except Exception as e:
        logger.error(f"❌ Failed to fetch network logs: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to fetch network logs"}
        )

# Feedback endpoints
@app.post("/feedback", tags=["Feedback"])
async def submit_feedback(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Read raw body
        body = await request.body()
        body_str = body.decode('utf-8')
        
        # Parse JSON manually
        data = json.loads(body_str)
        data["user_id"] = current_user.id
        
        # Ensure all fields are properly handled, including NULL values
        feedback_data = {
            "user_id": current_user.id,
            "overall_satisfaction": data.get("overall_satisfaction"),
            "response_time": data.get("response_time"),
            "usability": data.get("usability"),
            "comments": data.get("comments"),
            "issue_type": data.get("issue_type"),  # This was missing
            "carrier": data.get("carrier", "Unknown"),
            "network_type": data.get("network_type"),  # This was missing
            "location": data.get("location", "Unknown"),
            "signal_strength": data.get("signal_strength"),  # This was missing
            "download_speed": data.get("download_speed"),  # This was missing
            "upload_speed": data.get("upload_speed"),  # This was missing
            "latency": data.get("latency"),  # This was missing
        }
        
        logger.info(f"📝 Feedback data received: {feedback_data}")
        
        db_feedback = create_feedback(db, feedback_data)
        
        logger.info(f"✅ Feedback submitted by user: {current_user.email}")
        return JSONResponse(content={
            "message": "Feedback submitted successfully",
            "feedback_id": db_feedback.id,
            "timestamp": db_feedback.timestamp.isoformat()
        })
    except json.JSONDecodeError as e:
        return JSONResponse(
            status_code=400,
            content={"detail": f"Invalid JSON format: {str(e)}"}
        )
    except Exception as e:
        logger.error(f"❌ Feedback submission failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to submit feedback"}
        )

@app.get("/feedback", tags=["Feedback"])
async def get_user_feedback(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        feedbacks = get_feedbacks(db, user_id=current_user.id, skip=skip, limit=limit)
        
        # Convert to JSON serializable format
        feedback_data = []
        for feedback in feedbacks:
            feedback_dict = {
                "id": feedback.id,
                "user_id": feedback.user_id,
                "overall_satisfaction": feedback.overall_satisfaction,
                "response_time": feedback.response_time,
                "usability": feedback.usability,
                "comments": feedback.comments,
                "issue_type": feedback.issue_type,
                "carrier": feedback.carrier,
                "network_type": feedback.network_type,
                "location": feedback.location,
                "signal_strength": feedback.signal_strength,
                "download_speed": feedback.download_speed,
                "upload_speed": feedback.upload_speed,
                "latency": feedback.latency,
                "timestamp": feedback.timestamp.isoformat()
            }
            feedback_data.append(feedback_dict)
        
        return JSONResponse(content=feedback_data)
    except Exception as e:
        logger.error(f"❌ Failed to fetch feedback: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to fetch feedback"}
        )

# Recommendations endpoint
@app.get("/recommendations/{location}", tags=["Recommendations"])
async def get_recommendations(
    location: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        recommendations = get_provider_recommendations(db, location)
        logger.info(f"✅ Recommendations fetched for location: {location}")
        return JSONResponse(content=recommendations)
    except Exception as e:
        logger.error(f"❌ Failed to fetch recommendations: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to fetch recommendations"}
        )

# User profile endpoint
@app.get("/profile", tags=["User"])
async def get_profile(current_user: User = Depends(get_current_user)):
    return JSONResponse(content={
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "provider": current_user.provider,
        "created_at": current_user.created_at.isoformat(),
        "is_active": current_user.is_active
    })

# Debug endpoint to echo request details
@app.post("/debug/echo", tags=["Debug"])
async def debug_echo(request: Request):
    try:
        # Get headers
        headers = dict(request.headers.items())
        
        # Get body
        body = await request.body()
        body_str = body.decode('utf-8')
        
        # Try to parse as JSON
        try:
            body_json = json.loads(body_str)
        except:
            body_json = None
            
        return {
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
            "raw_body": body_str,
            "parsed_body": body_json,
            "content_type": headers.get("content-type", ""),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

# Debug endpoints (remove in production)
@app.get("/debug/database", tags=["Debug"])
async def debug_database():
    try:
        connection_info = get_connection_info()
        return {
            "database_info": connection_info,
            "environment_vars": {
                "DATABASE_URL": "***" if os.getenv("DATABASE_URL") else None,
                "SUPABASE_DATABASE_URL": "***" if os.getenv("SUPABASE_DATABASE_URL") else None,
                "RENDER_SERVICE_NAME": os.getenv("RENDER_SERVICE_NAME"),
                "SECRET_KEY": "***" if os.getenv("SECRET_KEY") else "using fallback"
            }
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/test-query", tags=["Debug"])
async def debug_test_query(db: Session = Depends(get_db)):
    try:
        result = db.execute(text("SELECT current_timestamp, version()"))
        row = result.fetchone()
        return {
            "timestamp": str(row[0]) if row else None,
            "database_version": str(row[1]) if row else None,
            "status": "success"
        }
    except Exception as e:
        return {"error": str(e), "status": "failed"}

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
