"""
Client Application 1 - Example app using SSO authentication
"""
from fastapi import FastAPI, Request, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import httpx
import uvicorn
from sxcore import fprint

app = FastAPI(title="Client App 1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SSO_SERVER = "http://localhost:8000"
CLIENT_ID = "client1"
CLIENT_SECRET = "client1_secret"
REDIRECT_URI = "http://localhost:8001/callback"

user_sessions = {}


@app.get("/", response_class=HTMLResponse)
async def root(app1_session: Optional[str] = Cookie(None)):
    """Home page - shows login or user info"""
    if app1_session and app1_session in user_sessions:
        user = user_sessions[app1_session]

        # Verify the access token is still valid on SSO server
        async with httpx.AsyncClient() as client:
            try:
                userinfo_response = await client.get(
                    f"{SSO_SERVER}/userinfo",
                    headers={"Authorization": f"Bearer {user['access_token']}"}
                )
                if userinfo_response.status_code != 200:
                    # Token is invalid, clear local session and redirect to login
                    fprint('session_invalid', f"Token invalid for {user['username']}, clearing session")
                    del user_sessions[app1_session]
                    response = RedirectResponse(url="/", status_code=302)
                    response.delete_cookie("app1_session")
                    return response
            except Exception:
                # If we can't verify, clear the session to be safe
                del user_sessions[app1_session]
                response = RedirectResponse(url="/", status_code=302)
                response.delete_cookie("app1_session")
                return response

        return f"""
        <html>
            <head><title>Client App 1</title></head>
            <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
                <h1>🎯 Client Application 1</h1>
                <div style="background: #d4edda; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <h3>Welcome, {user['username']}!</h3>
                    <p>You are successfully authenticated via SSO.</p>
                    <p><strong>User Info:</strong></p>
                    <ul>
                        <li>Username: {user['username']}</li>
                        <li>App: Client Application 1</li>
                        <li>Authenticated: ✓</li>
                    </ul>
                </div>
                <div style="margin: 20px 0;">
                    <a href="/protected" style="display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">
                        Access Protected Resource
                    </a>
                    <a href="/logout" style="display: inline-block; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin-left: 10px;">
                        Logout
                    </a>
                </div>
                <p style="margin-top: 40px; color: #666;">
                    Try accessing <a href="http://localhost:8002" target="_blank">Client App 2</a> -
                    you should be automatically logged in!
                </p>
            </body>
        </html>
        """

    return f"""
    <html>
        <head><title>Client App 1</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h1>🎯 Client Application 1</h1>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <p>Welcome to Client Application 1. Please sign in to continue.</p>
            </div>
            <a href="/login" style="display: inline-block; padding: 15px 30px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; font-size: 16px;">
                Sign in with SSO
            </a>
            <p style="margin-top: 40px; color: #666;">
                This is a demo client application that uses centralized SSO for authentication.
            </p>
        </body>
    </html>
    """


@app.get("/login")
async def login():
    """Redirect to SSO server for authentication"""
    auth_url = fprint('req', f"{SSO_SERVER}/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code")
    return RedirectResponse(url=auth_url)


@app.get("/callback")
async def callback(code: str):
    """Handle OAuth callback from SSO server"""
    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                f"{SSO_SERVER}/token",
                json={
                    "code": code,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "redirect_uri": REDIRECT_URI
                }
            )

            if token_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to exchange code for token")

            token_data = token_response.json()
            access_token = token_data["access_token"]

            userinfo_response = await client.get(
                f"{SSO_SERVER}/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if userinfo_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user info")

            user_data = userinfo_response.json()

            import secrets
            session_id = secrets.token_urlsafe(32)
            user_sessions[session_id] = {
                "username": user_data["username"],
                "access_token": access_token
            }

            response = RedirectResponse(url="/", status_code=302)
            response.set_cookie(
                key="app1_session",
                value=session_id,
                httponly=True,
                max_age=3600
            )
            return response

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@app.get("/protected", response_class=HTMLResponse)
async def protected(app1_session: Optional[str] = Cookie(None)):
    """Protected resource that requires authentication"""
    if not app1_session or app1_session not in user_sessions:
        return RedirectResponse(url="/login")

    user = user_sessions[app1_session]

    # Verify the access token is still valid on SSO server
    async with httpx.AsyncClient() as client:
        try:
            userinfo_response = await client.get(
                f"{SSO_SERVER}/userinfo",
                headers={"Authorization": f"Bearer {user['access_token']}"}
            )
            if userinfo_response.status_code != 200:
                # Token is invalid, clear local session and redirect to login
                fprint('session_invalid', f"Token invalid for {user['username']}, clearing session")
                del user_sessions[app1_session]
                response = RedirectResponse(url="/login", status_code=302)
                response.delete_cookie("app1_session")
                return response
        except Exception:
            # If we can't verify, clear the session to be safe
            del user_sessions[app1_session]
            response = RedirectResponse(url="/login", status_code=302)
            response.delete_cookie("app1_session")
            return response

    return f"""
    <html>
        <head><title>Protected Resource - App 1</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h1>🔒 Protected Resource</h1>
            <div style="background: #fff3cd; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <p>This is a protected resource in Client Application 1.</p>
                <p>Only authenticated users can see this content.</p>
                <p><strong>Authenticated as:</strong> {user['username']}</p>
            </div>
            <a href="/" style="display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">
                Back to Home
            </a>
        </body>
    </html>
    """


@app.get("/logout")
async def logout(app1_session: Optional[str] = Cookie(None)):
    """Logout from this application"""
     # Get the access token before deleting the session
    access_token = None
    if app1_session and app1_session in user_sessions:
        access_token = user_sessions[app1_session].get("access_token")
        del user_sessions[app1_session]

    # Call SSO server logout to invalidate the SSO session
    if access_token:
        async with httpx.AsyncClient() as client:
            try:
                await client.post(
                    f"{SSO_SERVER}/logout",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
            except Exception:
                pass  # Continue logout even if SSO logout fails
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("app1_session")
    response.delete_cookie("sso_session")  
    return response


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "app": "client1", "sso_server": SSO_SERVER}


if __name__ == "__main__":
    print("Starting Client App 1 on http://localhost:8001")
    print(f"SSO Server: {SSO_SERVER}")
    uvicorn.run(app, host="0.0.0.0", port=8001)
