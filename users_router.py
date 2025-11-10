from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.orm import Session

from database import get_db
import models
from schemas import UserInfo


router = APIRouter(tags=["users"])


@router.get("/user-profile/{user_id}")
def get_user_profile(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    auth = db.query(models.Auth).filter(models.Auth.user_id == user_id).first()

    return {
        "id": user.id,
        "name": user.name,
        "created_at": user.created_at,
        "role": auth.role if auth else None,
        "is_online": auth.is_online if auth else False,
        "last_login": auth.last_login if auth else None,
    }


@router.get("/users-with-info")
def list_users_with_info(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    all: bool = Query(False, description="Вернуть всех пользователей без пагинации"),
    db: Session = Depends(get_db),
):
    total = db.query(models.User).count()
    if all:
        page = 1
        limit = total if total > 0 else 1
        offset = 0
    else:
        offset = (page - 1) * limit

    users = (
        db.query(models.User)
        .order_by(models.User.id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    user_ids = [u.id for u in users]
    auth_map = {
        a.user_id: a for a in db.query(models.Auth).filter(models.Auth.user_id.in_(user_ids)).all()
    } if user_ids else {}

    items = []
    for u in users:
        a = auth_map.get(u.id)
        items.append({
            "id": u.id,
            "name": u.name,
            "created_at": u.created_at,
            "role": a.role if a else None,
            "is_online": a.is_online if a else False,
            "last_login": a.last_login if a else None,
        })

    return {
        "users": items,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": 1 if all else (total + limit - 1) // limit,
        },
    }


@router.get("/users", response_model=list[UserInfo])
def list_all_users(db: Session = Depends(get_db)):
    users = (
        db.query(models.User)
        .order_by(models.User.id.asc())
        .all()
    )
    user_ids = [u.id for u in users]
    auth_map = {
        a.user_id: a for a in db.query(models.Auth).filter(models.Auth.user_id.in_(user_ids)).all()
    } if user_ids else {}

    items = []
    for u in users:
        a = auth_map.get(u.id)
        items.append({
            "id": u.id,
            "name": u.name,
            "created_at": u.created_at,
            "role": a.role if a else None,
            "is_online": a.is_online if a else False,
            "last_login": a.last_login if a else None,
        })

    return items
