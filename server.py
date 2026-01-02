from fastapi import FastAPI, APIRouter, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr, field_validator
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import time
import re
import hashlib
import secrets


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Admin API Key for viewing submissions (set in environment variables)
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'change-this-key-in-production')

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Rate limiting storage (in production, use Redis)
rate_limit_store = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 5  # max contact form submissions per window


def verify_admin_key(api_key: str = Header(None, alias="X-Admin-Key")):
    """Verify the admin API key"""
    if not api_key or api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Add 'X-Admin-Key' header."
        )
    return True


# Define Models
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")  # Ignore MongoDB's _id field
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str


# Contact Form Models
class ContactFormSubmission(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=255)
    message: str = Field(..., min_length=10, max_length=2000)
    honeypot: Optional[str] = Field(default=None)  # Honeypot field for bot detection
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_hash: Optional[str] = None  # Hashed IP for privacy
    is_spam: bool = False
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        # Basic email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, v):
            raise ValueError('Invalid email format')
        return v.lower().strip()
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        # Remove excessive whitespace and validate
        cleaned = ' '.join(v.split())
        if len(cleaned) < 2:
            raise ValueError('Name must be at least 2 characters')
        # Check for suspicious patterns (all numbers, special chars only)
        if re.match(r'^[0-9]+$', cleaned) or re.match(r'^[^a-zA-Z]+$', cleaned):
            raise ValueError('Invalid name format')
        return cleaned
    
    @field_validator('message')
    @classmethod
    def validate_message(cls, v):
        # Remove excessive whitespace
        cleaned = ' '.join(v.split())
        if len(cleaned) < 10:
            raise ValueError('Message must be at least 10 characters')
        return cleaned


class ContactFormCreate(BaseModel):
    name: str
    email: str
    message: str
    honeypot: Optional[str] = None  # Should be empty for real users
    captcha_token: Optional[str] = None  # For future CAPTCHA integration


class ContactFormResponse(BaseModel):
    success: bool
    message: str
    id: Optional[str] = None


# Rate limiting helper
def check_rate_limit(ip_address: str) -> bool:
    """Check if IP has exceeded rate limit. Returns True if allowed."""
    current_time = time.time()
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]
    
    if ip_hash in rate_limit_store:
        requests = rate_limit_store[ip_hash]
        # Clean old requests
        requests = [t for t in requests if current_time - t < RATE_LIMIT_WINDOW]
        rate_limit_store[ip_hash] = requests
        
        if len(requests) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        
        rate_limit_store[ip_hash].append(current_time)
    else:
        rate_limit_store[ip_hash] = [current_time]
    
    return True


def detect_spam(submission: ContactFormCreate, ip_address: str) -> tuple[bool, str]:
    """Detect spam submissions. Returns (is_spam, reason)."""
    
    # 1. Honeypot check - if filled, it's a bot
    if submission.honeypot and len(submission.honeypot) > 0:
        return True, "Honeypot triggered"
    
    # 2. Check for common spam patterns in message
    spam_keywords = [
        'viagra', 'casino', 'lottery', 'winner', 'click here',
        'buy now', 'free money', 'bitcoin profit', 'earn money fast',
        'nigerian prince', 'inheritance', 'million dollars'
    ]
    message_lower = submission.message.lower()
    for keyword in spam_keywords:
        if keyword in message_lower:
            return True, f"Spam keyword detected: {keyword}"
    
    # 3. Check for excessive URLs
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, submission.message)
    if len(urls) > 2:
        return True, "Too many URLs in message"
    
    # 4. Check for repetitive characters
    if re.search(r'(.)\1{10,}', submission.message):
        return True, "Repetitive characters detected"
    
    return False, ""


# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "Hello World"}


@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    # Convert to dict and serialize datetime to ISO string for MongoDB
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    _ = await db.status_checks.insert_one(doc)
    return status_obj


@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    # Exclude MongoDB's _id field from the query results
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    # Convert ISO string timestamps back to datetime objects
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks


# Contact Form Endpoint
@api_router.post("/contact", response_model=ContactFormResponse)
async def submit_contact_form(submission: ContactFormCreate, request: Request):
    """
    Handle contact form submissions with spam protection.
    
    Security measures implemented:
    1. Rate limiting (5 requests per minute per IP)
    2. Honeypot field for bot detection
    3. Input validation and sanitization
    4. Spam keyword detection
    5. URL limit checking
    6. IP hashing for privacy
    """
    try:
        # Get client IP (handle proxy headers)
        client_ip = request.headers.get('X-Forwarded-For', request.client.host)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        # 1. Rate limiting check
        if not check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later."
            )
        
        # 2. Spam detection
        is_spam, spam_reason = detect_spam(submission, client_ip)
        
        # 3. Create submission record
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        
        contact_entry = ContactFormSubmission(
            name=submission.name,
            email=submission.email,
            message=submission.message,
            honeypot=submission.honeypot,
            ip_hash=ip_hash,
            is_spam=is_spam
        )
        
        # 4. If spam, reject immediately without storing
        if is_spam:
            logger.warning(f"Spam detected from {ip_hash}: {spam_reason}")
            raise HTTPException(
                status_code=400,
                detail="Your message was flagged as spam. Please try again with a legitimate message."
            )
        
        # 5. Store valid submission in database
        doc = contact_entry.model_dump()
        doc['timestamp'] = doc['timestamp'].isoformat()
        
        await db.contact_submissions.insert_one(doc)
        
        # 6. Log the submission (for monitoring)
        logger.info(f"Contact form submission: {contact_entry.id}")
        
        return ContactFormResponse(
            success=True,
            message="Thank you for your message! I will get back to you within 24 hours.",
            id=contact_entry.id
        )
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Contact form error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred. Please try again later."
        )


@api_router.get("/contact/submissions", response_model=List[dict])
async def get_contact_submissions(api_key: str = Header(None, alias="X-Admin-Key")):
    """Get all contact submissions (protected - requires API key)"""
    verify_admin_key(api_key)
    
    submissions = await db.contact_submissions.find(
        {}, 
        {"_id": 0, "ip_hash": 0}  # Exclude sensitive fields
    ).sort("timestamp", -1).to_list(100)
    
    return submissions


@api_router.get("/contact/submissions/clean", response_model=List[dict])
async def get_clean_contact_submissions(api_key: str = Header(None, alias="X-Admin-Key")):
    """Get only non-spam contact submissions (protected - requires API key)"""
    verify_admin_key(api_key)
    
    submissions = await db.contact_submissions.find(
        {"is_spam": False}, 
        {"_id": 0, "ip_hash": 0}
    ).sort("timestamp", -1).to_list(100)
    
    return submissions


@api_router.delete("/contact/submissions/{submission_id}")
async def delete_submission(submission_id: str, api_key: str = Header(None, alias="X-Admin-Key")):
    """Delete a specific submission (protected - requires API key)"""
    verify_admin_key(api_key)
    
    result = await db.contact_submissions.delete_one({"id": submission_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    return {"success": True, "message": "Submission deleted"}


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
