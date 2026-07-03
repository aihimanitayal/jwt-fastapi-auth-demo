"""
JWT Auth + Token Refresh Demo — FastAPI

Companion code for my blog post:
JWT Authentication & Token Refresh in FastAPI: A Practical Guide
https://himanitayal.hashnode.dev/

Demonstrates:
- Access/refresh token separation with different lifetimes
- Refresh token rotation (old token invalidated on every use)
- httpOnly, secure, samesite cookie storage for the refresh token
- Token-type checking to prevent refresh tokens authenticating API requests
"""

from fastapi import FastAPI, Depends, HTTPException, Response, Cookie
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from app.auth import (
    issue_tokens,
    rotate_refresh_token,
    verify_token,
    revoke_refresh_token,
)

app = FastAPI(title="JWT Auth Demo")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)


class LoginRequest(BaseModel):
    user_id: str  # demo only — replace with real credential verification


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        return verify_token(token, expected_type="access")
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.post("/login")
def login(body: LoginRequest, response: Response):
    """Demo login — in production, verify credentials before issuing tokens."""
    tokens = issue_tokens(body.user_id)

    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        secure=True,       # requires HTTPS in production
        samesite="strict",
        max_age=7 * 24 * 60 * 60,
    )
    return {"access_token": tokens["access_token"]}


@app.post("/refresh")
def refresh(response: Response, refresh_token: str | None = Cookie(default=None)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token provided")

    try:
        tokens = rotate_refresh_token(refresh_token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=7 * 24 * 60 * 60,
    )
    return {"access_token": tokens["access_token"]}


@app.post("/logout")
def logout(response: Response, user: dict = Depends(get_current_user)):
    revoke_refresh_token(user["sub"])
    response.delete_cookie("refresh_token")
    return {"message": "Logged out"}


@app.get("/me")
def read_current_user(user: dict = Depends(get_current_user)):
    return {"user_id": user["sub"]}
