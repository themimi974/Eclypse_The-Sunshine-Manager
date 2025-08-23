from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import os

from database import SessionLocal
from models import User

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_KEY")  # En prod, définir via variable d'env
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        return username, role
    except JWTError:
        return None, None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    username, role = decode_access_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

def get_admin_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Permet seulement aux rôles admin / master d'accéder à la ressource.
    """
    username, role = decode_access_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user or user.role not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="You are not admin or master")

    return user
