from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List

# User schemas
class UserBase(BaseModel):
    username: str
    email: str
    provider: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime
    is_active: bool
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# Feedback schemas
class FeedbackBase(BaseModel):
    overall_satisfaction: int  # 1-5
    response_time: int        # 1-5
    usability: int           # 1-5
    comments: Optional[str] = None
    issue_type: Optional[str] = None
    carrier: str
    network_type: Optional[str] = None
    location: str
    signal_strength: Optional[int] = None
    download_speed: Optional[float] = None
    upload_speed: Optional[float] = None
    latency: Optional[int] = None

class FeedbackCreate(FeedbackBase):
    pass

class FeedbackResponse(FeedbackBase):
    id: int
    user_id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

# Network Log schemas
class NetworkLogBase(BaseModel):
    carrier: str
    network_type: Optional[str] = None
    signal_strength: Optional[int] = None
    download_speed: Optional[float] = None
    upload_speed: Optional[float] = None
    latency: Optional[int] = None
    jitter: Optional[float] = None
    packet_loss: Optional[float] = None
    location: str
    device_info: Optional[str] = None
    app_version: Optional[str] = None

class NetworkLogCreate(NetworkLogBase):
    pass

class NetworkLogResponse(NetworkLogBase):
    id: int
    user_id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

# Recommendation schemas
class RecommendationResponse(BaseModel):
    carrier: str
    score: float
    avg_download_speed: float
    avg_upload_speed: float
    avg_latency: float
    avg_signal_strength: float
    total_samples: int
    recommendation_reason: str
