#!/bin/env -S pyboots --html http://automationmd/virtualenv/metrics/requirements.txt  --require 3.12 --rebuild-on-changes


"""
SSO Server - Central authentication server for single sign-on
"""
from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import secrets
import hashlib
from typing import Optional, Dict
import uvicorn
from sxcore import fprint

app = FastAPI(title="SSO Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (use database in production)
users_db = {
    "alice": hashlib.sha256("password123".encode()).hexdigest(),
    "bob": hashlib.sha256("password456".encode()).hexdigest(),
}

sessions: Dict[str, dict] = {}
auth_codes: Dict[str, dict] = {}
registered_clients = {
    "client1": {
        "secret": "client1_secret",
        "redirect_uri": "http://localhost:8001/callback"
    },
    "client2": {
        "secret": "client2_secret",
        "redirect_uri": "http://localhost:8002/callback"
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRequest(BaseModel):
    code: str
    client_id: str
    client_secret: str
    redirect_uri: str


@app.get("/")
async def root():
    return {"message": "SSO Server is running", "endpoints": {
        "login_page": "/login",
        "authorize": "/authorize",
        "token": "/token",
        "userinfo": "/userinfo"
    }}


@app.get("/login", response_class=HTMLResponse)
async def login_page(redirect_uri: Optional[str] = None, client_id: Optional[str] = None):
    """Display login form"""
    redirect_param = f'<input type="hidden" name="redirect_uri" value="{redirect_uri}">' if redirect_uri else ''
    client_param = f'<input type="hidden" name="client_id" value="{client_id}">' if client_id else ''

    return f"""
    <html>
        <head><title>SSO Login</title></head>
        <body style="font-family: Arial; max-width: 400px; margin: 100px auto;">
            <h2>Single Sign-On Login</h2>
            <form action="/login" method="post">
                <div style="margin: 10px 0;">
                    <label>Username:</label><br>
                    <input type="text" name="username" required style="width: 100%; padding: 8px;">
                    <small style="color: #666;">Try: alice or bob</small>
                </div>
                <div style="margin: 10px 0;">
                    <label>Password:</label><br>
                    <input type="password" name="password" required style="width: 100%; padding: 8px;">
                    <small style="color: #666;">alice: password123, bob: password456</small>
                </div>
                {redirect_param}
                {client_param}
                <button type="submit" style="width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; margin-top: 10px;">
                    Sign In
                </button>
            </form>
        </body>
    </html>
    """


@app.post("/login")
async def login(
    request: Request,
    username: Optional[str] = None,
    password: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    client_id: Optional[str] = None,
    sso_session: Optional[str] = Cookie(None)
):
    """Process login and create session"""
    # Try to get from form data if not in query params
    if username is None or password is None:
        form_data = await request.form()
        username = username or form_data.get("username")
        password = password or form_data.get("password")
        redirect_uri = redirect_uri or form_data.get("redirect_uri")
        client_id = client_id or form_data.get("client_id")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username not in users_db or users_db[username] != password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Invalidate existing SSO session if user is switching accounts
    # (One session per browser, like Gmail)
    if sso_session and sso_session in sessions:
        old_user = sessions[sso_session].get("username")
        if old_user != username:
            fprint('session_switch', f"User switching from {old_user} to {username} - invalidating old sessions")
            # Delete the old SSO session
            del sessions[sso_session]
            # Also invalidate all access tokens for the old user
            # This ensures clean switch between accounts
            tokens_to_delete = [
                token for token, session_data in sessions.items()
                if session_data.get("username") == old_user
            ]
            for token in tokens_to_delete:
                fprint('session_switch', f"Invalidating old access token for {old_user}")
                del sessions[token]

    session_token = secrets.token_urlsafe(32)
    sessions[session_token] = {
        "username": username,
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(hours=24)
    }

    if redirect_uri and client_id:
        auth_code = secrets.token_urlsafe(32)
        auth_codes[auth_code] = {
            "username": username,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=5)
        }

        response = RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=302)
        response.set_cookie(
            key="sso_session",
            value=session_token,
            httponly=True,
            max_age=86400,
            samesite="lax"
        )
        return response

    return {
        "status": "success",
        "session_token": session_token,
        "username": username
    }


@app.get("/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    sso_session: Optional[str] = Cookie(None)
):
    """OAuth2-style authorization endpoint"""
    if client_id not in registered_clients:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if registered_clients[client_id]["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    if sso_session and sso_session in sessions:
        session = sessions[sso_session]
        if session["expires_at"] > datetime.now():
            auth_code = secrets.token_urlsafe(32)
            auth_codes[auth_code] = {
                "username": session["username"],
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=5)
            }
            return RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=302)

    return RedirectResponse(
        url=f"/login?redirect_uri={redirect_uri}&client_id={client_id}",
        status_code=302
    )


@app.post("/token")
async def token(request: TokenRequest):
    """Exchange authorization code for access token"""
    if request.code not in auth_codes:
        raise HTTPException(status_code=400, detail="Invalid authorization code")

    auth_data = auth_codes[request.code]

    if auth_data["expires_at"] < datetime.now():
        del auth_codes[request.code]
        raise HTTPException(status_code=400, detail="Authorization code expired")

    if auth_data["client_id"] != request.client_id:
        raise HTTPException(status_code=400, detail="Client ID mismatch")

    if request.client_id not in registered_clients:
        raise HTTPException(status_code=400, detail="Invalid client")

    if registered_clients[request.client_id]["secret"] != request.client_secret:
        raise HTTPException(status_code=401, detail="Invalid client secret")

    if auth_data["redirect_uri"] != request.redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI mismatch")

    access_token = secrets.token_urlsafe(32)
    sessions[access_token] = {
        "username": auth_data["username"],
        "client_id": request.client_id,
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(hours=1)
    }

    del auth_codes[request.code]

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "username": auth_data["username"]
    }


@app.get("/userinfo")
async def userinfo(request: Request):
    """Get user information from access token"""
    authorization = request.headers.get("authorization")
    fprint('auth_header', f"Authorization: {authorization}")

    if not authorization or not authorization.startswith("Bearer "):
        fprint('error', "Missing or invalid auth header")
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = authorization.replace("Bearer ", "")
    fprint('token_check', f"Token: {token[:20]}... | Sessions: {len(sessions)} keys")

    if token not in sessions:
        fprint('error', f"Token not found in sessions. Available keys: {list(sessions.keys())[:2]}")
        raise HTTPException(status_code=401, detail="Invalid token")

    session = sessions[token]

    if session["expires_at"] < datetime.now():
        del sessions[token]
        raise HTTPException(status_code=401, detail="Token expired")

    return {
        "username": session["username"],
        "authenticated": True
    }


@app.post("/logout")
async def logout(request: Request, sso_session: Optional[str] = Cookie(None)):
    """Logout and invalidate ALL sessions for the user (SSO-wide logout)"""
    username = None

    # Check for Bearer token in Authorization header
    authorization = request.headers.get("authorization")
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        if token in sessions:
            username = sessions[token].get("username")
            fprint('logout', f"Invalidating access token session for {username}")
            del sessions[token]

    # Also check for SSO session cookie
    if sso_session and sso_session in sessions:
        username = username or sessions[sso_session].get("username")
        fprint('logout', f"Invalidating SSO session for {username}")
        del sessions[sso_session]

    # Invalidate ALL other sessions for this user (access tokens from other clients)
    # This ensures true SSO logout - logout from one app logs you out everywhere
    if username:
        tokens_to_delete = [
            token for token, session_data in sessions.items()
            if session_data.get("username") == username
        ]
        for token in tokens_to_delete:
            fprint('logout', f"Invalidating additional session: {token[:20]}...")
            del sessions[token]

    response = Response(content='{"status": "logged out"}', media_type="application/json")
    response.delete_cookie("sso_session")
    return response


if __name__ == "__main__":
    print("Starting SSO Server on http://localhost:8000")
    print("Registered users: alice (password123), bob (password456)")
    print("Registered clients: client1, client2")
    uvicorn.run(app, host="", port=8000)
