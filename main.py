# main.py - Final Corrected Version

# --- 1. Imports ---
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytz
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import (Column, DateTime, ForeignKey, Integer, String,
                        create_engine)
from sqlalchemy.orm import Session, relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# --- 2. Configuration ---
SECRET_KEY = "my-secret-key-for-this-project"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
IST = pytz.timezone('Asia/Kolkata')

# --- 3. Database Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./fitness_studio.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 4. Database Models (Tables) ---
class User(Base):
    _tablename_ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    bookings = relationship("Booking", back_populates="user")

class FitnessClass(Base):
    _tablename_ = "classes"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    date_time = Column(DateTime(timezone=True))
    instructor = Column(String)
    available_slots = Column(Integer)
    bookings = relationship("Booking", back_populates="fitness_class")

class Booking(Base):
    _tablename_ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    class_id = Column(Integer, ForeignKey("classes.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="bookings")
    fitness_class = relationship("FitnessClass", back_populates="bookings")

Base.metadata.create_all(bind=engine)

# --- 5. Pydantic Schemas (Data Shapes) ---
class UserCreate(BaseModel):
    name: str; email: EmailStr; password: str
class UserOut(BaseModel):
    id: int; name: str; email: EmailStr
    class Config: orm_mode = True
class ClassCreate(BaseModel):
    name: str; date_time: datetime; instructor: str; available_slots: int
class ClassOut(ClassCreate):
    id: int
    class Config: orm_mode = True
class BookingCreate(BaseModel):
    class_id: int
class BookingOut(BaseModel):
    id: int; fitness_class: ClassOut
    class Config: orm_mode = True
class Token(BaseModel):
    access_token: str; token_type: str

# --- 6. Security & Dependencies ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email: raise HTTPException(status_code=401, detail="Invalid Token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")
    user = db.query(User).filter(User.email == email).first()
    if not user: raise HTTPException(status_code=401, detail="User not found")
    return user

# --- 7. FastAPI App & Endpoints ---
app = FastAPI(title="Fitness API")

@app.post("/signup", tags=["User"])
def signup(data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=data.name, email=data.email, hashed_password=pwd_context.hash(data.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"id": user.id, "name": user.name, "email": user.email}

@app.post("/login", response_model=Token, tags=["User"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not pwd_context.verify(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": user.email, "exp": datetime.now(timezone.utc) + expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/classes", response_model=ClassOut, tags=["Classes"])
def create_class(data: ClassCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    db_class = FitnessClass(**data.dict())
    db_class.date_time = data.date_time.astimezone(IST)
    db.add(db_class); db.commit(); db.refresh(db_class)
    return db_class

@app.get("/classes", response_model=List[ClassOut], tags=["Classes"])
def get_classes(db: Session = Depends(get_db)):
    return db.query(FitnessClass).filter(FitnessClass.date_time >= datetime.now(IST)).all()

@app.post("/book", response_model=BookingOut, tags=["Bookings"])
def book_class(req: BookingCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    cls = db.query(FitnessClass).filter(FitnessClass.id == req.class_id).first()
    if not cls: raise HTTPException(status_code=404, detail="Class not found")
    if cls.available_slots <= 0: raise HTTPException(status_code=400, detail="Class is full")
    if db.query(Booking).filter(Booking.class_id == req.class_id, Booking.user_id == user.id).first():
        raise HTTPException(status_code=400, detail="You have already booked this class")
    
    cls.available_slots -= 1
    booking = Booking(class_id=req.class_id, user_id=user.id)
    db.add(booking); db.add(cls); db.commit(); db.refresh(booking)
    return booking

@app.get("/bookings", response_model=List[BookingOut], tags=["Bookings"])
def get_my_bookings(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Booking).filter(Booking.user_id == user.id).all()