# QoE App Backend

Quality of Experience monitoring and feedback API built with FastAPI.

## 🚀 Features

- User authentication (JWT-based)
- Network performance logging
- User feedback collection
- Provider recommendations
- Real-time health monitoring
- Automatic database initialization

## 🔧 Tech Stack

- **FastAPI** - Modern Python web framework
- **SQLAlchemy** - Database ORM
- **PostgreSQL** - Database (Supabase)
- **JWT** - Authentication
- **Render** - Hosting platform

## 📚 API Documentation

Once deployed, visit `/docs` for interactive API documentation.

## 🌐 Live API

- **Health Check**: `GET /health`
- **API Docs**: `GET /docs`
- **Authentication**: `POST /auth/register`, `POST /auth/login`
- **Network Logs**: `POST /network-logs`
- **Feedback**: `POST /feedback`

## 🔐 Environment Variables

Required environment variables:
- `SECRET_KEY` - JWT secret key
- `SUPABASE_DATABASE_URL` - Database connection string

## 📱 Mobile App Integration

This backend is designed to work with the QoE Flutter mobile application.
