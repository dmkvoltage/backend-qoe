from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship  # Fixed import statement
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    provider = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)
    
    # Relationships
    feedbacks = relationship("Feedback", back_populates="user")
    network_logs = relationship("NetworkLog", back_populates="user")

class Feedback(Base):
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Feedback ratings (1-5 scale)
    overall_satisfaction = Column(Integer, nullable=False)
    response_time = Column(Integer, nullable=False)
    usability = Column(Integer, nullable=False)
    
    # Optional feedback details
    comments = Column(Text, nullable=True)
    issue_type = Column(String, nullable=True)
    
    # Network context
    carrier = Column(String, nullable=False)
    network_type = Column(String, nullable=True)
    
    # Location and timing
    location = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Network metrics at time of feedback
    signal_strength = Column(Integer, nullable=True)
    download_speed = Column(Float, nullable=True)
    upload_speed = Column(Float, nullable=True)
    latency = Column(Integer, nullable=True)
    
    # Relationship
    user = relationship("User", back_populates="feedbacks")

class NetworkLog(Base):
    __tablename__ = "network_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Network provider/carrier
    carrier = Column(String, nullable=False, index=True)
    network_type = Column(String, nullable=True)
    
    # Network performance metrics
    signal_strength = Column(Integer, nullable=True)
    download_speed = Column(Float, nullable=True)
    upload_speed = Column(Float, nullable=True)
    latency = Column(Integer, nullable=True)
    jitter = Column(Float, nullable=True)
    packet_loss = Column(Float, nullable=True)
    
    # Location and timing
    location = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Additional context
    device_info = Column(String, nullable=True)
    app_version = Column(String, nullable=True)
    
    # Relationship
    user = relationship("User", back_populates="network_logs")
