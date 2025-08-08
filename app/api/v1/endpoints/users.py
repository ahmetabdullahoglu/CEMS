"""
Module: users
Purpose: User management endpoints: CRUD, roles management
Author: CEMS Development Team
Date: 2024
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.schemas.user import UserCreate, UserUpdate, UserResponse
from app.api.deps import get_db, get_current_active_user
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("/", response_model=list[UserResponse])
def list_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    service = UserService(db)
    return service.get_users(skip=skip, limit=limit)

@router.post("/", response_model=UserResponse)
def create_user(data: UserCreate, db: Session = Depends(get_db)):
    service = UserService(db)
    return service.create_user(data)

@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    service = UserService(db)
    return service.get_user_by_id(user_id)

@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db)):
    service = UserService(db)
    return service.update_user(user_id, data)

@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    service = UserService(db)
    service.delete_user(user_id)
    return {"detail": "User deleted"}

@router.post("/{user_id}/roles")
def add_role_to_user(user_id: int, role_id: int, db: Session = Depends(get_db)):
    service = UserService(db)
    service.assign_role(user_id, role_id)
    return {"detail": "Role assigned to user"}

@router.delete("/{user_id}/roles/{role_id}")
def remove_role_from_user(user_id: int, role_id: int, db: Session = Depends(get_db)):
    service = UserService(db)
    service.remove_role(user_id, role_id)
    return {"detail": "Role removed from user"}
