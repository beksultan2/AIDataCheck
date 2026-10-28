import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models import RefreshToken, UserProfile
from schemas import (
    AccessTokenOut,
    LoginIn,
    MessageOut,
    RefreshIn,
    RegisterIn,
    TokenOut,
    UpdateIn,
    UserOut,
)
from security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["Auth"])
bearer = HTTPBearer()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> UserProfile:
    try:
        payload = decode_token(creds.credentials, "access")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

    user = db.get(UserProfile, int(payload["sub"]))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


def _issue_tokens(user: UserProfile, db: Session) -> TokenOut:
    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    db.add(RefreshToken(user_id=user.id, token=refresh))
    db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)


def _check_unique(db: Session, username=None, email=None, exclude_id=None):
    if username:
        q = (db.query(UserProfile).filter(UserProfile.username == username))
        if exclude_id:
            q = q.filter(UserProfile.id != exclude_id)
        if q.first():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username already taken")
    if email:
        q = db.query(UserProfile).filter(UserProfile.email == email)
        if exclude_id:
            q = q.filter(UserProfile.id != exclude_id)
        if q.first():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")


@router.post("/register/", response_model=MessageOut, summary="Register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    _check_unique(db, username=data.username, email=data.email)
    user = UserProfile(
        first_name=data.first_name,
        last_name=data.last_name,
        username=data.username,
        email=data.email,
        password=hash_password(data.password),
        status=data.status,
    )
    db.add(user)
    db.commit()
    return MessageOut(message="Вы зарегистрировались.")


@router.post("/login/", response_model=TokenOut, summary="Login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(UserProfile).filter(UserProfile.username == data.username).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    return _issue_tokens(user, db)


@router.post("/logout/", response_model=MessageOut, summary="Logout")
def logout(
    data: RefreshIn,
    user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token == data.refresh_token, RefreshToken.user_id == user.id)
        .first()
    )
    if not token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Refresh token not found")
    db.delete(token)
    db.commit()
    return MessageOut(message="Вы вышли из системы.")


@router.post("/refresh/", response_model=AccessTokenOut, summary="Refresh Token")
def refresh(data: RefreshIn, db: Session = Depends(get_db)):
    try:
        payload = decode_token(data.refresh_token, "refresh")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")

    stored = (db.query(RefreshToken).filter(RefreshToken.token == data.refresh_token).first())
    if not stored:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token revoked")

    return AccessTokenOut(access_token=create_access_token(int(payload["sub"])))
@router.get("/me/", response_model=UserOut, summary="Me")
def me(user: UserProfile = Depends(get_current_user)):
    return user


@router.put("/me/update/", response_model=UserOut, summary="Update Me")
def update_me(
    data: UpdateIn,
    user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    changes = data.model_dump(exclude_unset=True)
    _check_unique(
        db,
        username=changes.get("username"),
        email=changes.get("email"),
        exclude_id=user.id,
    )
    if "password" in changes:
        changes["password"] = hash_password(changes["password"])
    for field, value in changes.items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/me/delete/", response_model=MessageOut, summary="Delete Me")
def delete_me(
    user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.delete(user)
    db.commit()
    return MessageOut(message="Аккаунт өчүрүлдү.")


@router.get("/verify/", response_model=MessageOut, summary="Verify Access Token")
def verify(user: UserProfile = Depends(get_current_user)):
    return MessageOut(message="Token is valid")
