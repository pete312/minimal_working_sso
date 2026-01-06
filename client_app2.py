"""
Client Application 2 - Example app using SSO authentication
"""
from fastapi import FastAPI, Request, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import httpx
import uvicorn
from sxcore import fprint

app = FastAPI(title="Client App 2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SSO_SERVER = "http://localhost:8000"
CLIENT_ID = "client2"
CLIENT_SECRET = "client2_secret"
REDIRECT_URI = "http://localhost:8002/callback"

user_sessions = {}


@app.get("/", response_class=HTMLResponse)
async def root(app2_session: Optional[str] = Cookie(None)):
    """Home page - shows login or user info"""
    if app2_session and app2_session in user_sessions:
        user = user_sessions[app2_session]

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
                    del user_sessions[app2_session]
                    response = RedirectResponse(url="/", status_code=302)
                    response.delete_cookie("app2_session")
                    return response
            except Exception:
                # If we can't verify, clear the session to be safe
                del user_sessions[app2_session]
                response = RedirectResponse(url="/", status_code=302)
                response.delete_cookie("app2_session")
                return response

        return f"""
        <html>
            <head><title>Client App 2</title></head>
            <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
                <h1>🚀 Client Application 2</h1>
                <div style="background: #cce5ff; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <h3>Hello, {user['username']}!</h3>
                    <p>You are successfully authenticated via SSO.</p>
                    <p><strong>User Info:</strong></p>
                    <ul>
                        <li>Username: {user['username']}</li>
                        <li>App: Client Application 2</li>
                        <li>Authenticated: ✓</li>
                    </ul>
                </div>
                <div style="margin: 20px 0;">
                    <a href="/dashboard" style="display: inline-block; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px;">
                        View Dashboard
                    </a>
                    <a href="/api-test" style="display: inline-block; padding: 10px 20px; background: #17a2b8; color: white; text-decoration: none; border-radius: 5px; margin-left: 10px;">
                        Test API
                    </a>
                    <a href="/logout" style="display: inline-block; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin-left: 10px;">
                        Logout
                    </a>
                </div>
                <p style="margin-top: 40px; color: #666;">
                    Try accessing <a href="http://localhost:8001" target="_blank">Client App 1</a> -
                    you should be automatically logged in!
                </p>
            </body>
        </html>
        """

    return f"""
    <html>
        <head><title>Client App 2</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h1>🚀 Client Application 2</h1>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <p>Welcome to Client Application 2. Please sign in to continue.</p>
            </div>
            <a href="/login" style="display: inline-block; padding: 15px 30px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; font-size: 16px;">
                Sign in with SSO
            </a>
            <p style="margin-top: 40px; color: #666;">
                This is another demo client application that uses the same SSO server.
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
                key="app2_session",
                value=session_id,
                httponly=True,
                max_age=3600
            )
            return response

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(app2_session: Optional[str] = Cookie(None)):
    """User dashboard - requires authentication"""
    if not app2_session or app2_session not in user_sessions:
        return RedirectResponse(url="/login")

    user = user_sessions[app2_session]

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
                del user_sessions[app2_session]
                response = RedirectResponse(url="/login", status_code=302)
                response.delete_cookie("app2_session")
                return response
        except Exception:
            # If we can't verify, clear the session to be safe
            del user_sessions[app2_session]
            response = RedirectResponse(url="/login", status_code=302)
            response.delete_cookie("app2_session")
            return response

    return f"""
    <html>
        <head><title>Dashboard - App 2</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h1>📊 User Dashboard</h1>
            <div style="background: #e7f3ff; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h3>Welcome to your dashboard, {user['username']}!</h3>
                <p>This is a protected dashboard in Client Application 2.</p>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 20px;">
                    <div style="background: white; padding: 15px; border-radius: 5px; border: 1px solid #ddd;">
                        <h4>Total Projects</h4>
                        <p style="font-size: 24px; margin: 0;">12</p>
                    </div>
                    <div style="background: white; padding: 15px; border-radius: 5px; border: 1px solid #ddd;">
                        <h4>Active Tasks</h4>
                        <p style="font-size: 24px; margin: 0;">7</p>
                    </div>
                </div>
            </div>
            <a href="/" style="display: inline-block; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px;">
                Back to Home
            </a>
        </body>
    </html>
    """


@app.get("/api-test", response_class=HTMLResponse)
async def api_test(app2_session: Optional[str] = Cookie(None)):
    """API test page - requires authentication"""
    if not app2_session or app2_session not in user_sessions:
        return RedirectResponse(url="/login")

    user = user_sessions[app2_session]

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
                del user_sessions[app2_session]
                response = RedirectResponse(url="/login", status_code=302)
                response.delete_cookie("app2_session")
                return response
        except Exception:
            # If we can't verify, clear the session to be safe
            del user_sessions[app2_session]
            response = RedirectResponse(url="/login", status_code=302)
            response.delete_cookie("app2_session")
            return response

    return f"""
    <html>
        <head><title>API Test - App 2</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h1>🔧 API Test Page</h1>
            <div style="background: #fff3cd; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <p>This page demonstrates API access with SSO authentication.</p>
                <p><strong>Current User:</strong> {user['username']}</p>
                <p><strong>Access Token (first 20 chars):</strong> {user['access_token'][:20]}...</p>
            </div>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h4>Example API Call:</h4>
                <pre style="background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto;">
curl -H "Authorization: Bearer YOUR_TOKEN" \\
     http://localhost:8000/userinfo
                </pre>
            </div>
            <a href="/" style="display: inline-block; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px;">
                Back to Home
            </a>
        </body>
    </html>
    """


@app.get("/logout")
async def logout(app2_session: Optional[str] = Cookie(None)):
    """Logout from this application and SSO server"""
    # Get the access token before deleting the session
    access_token = None
    if app2_session and app2_session in user_sessions:
        access_token = user_sessions[app2_session].get("access_token")
        del user_sessions[app2_session]

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
    response.delete_cookie("app2_session")
    response.delete_cookie("sso_session")  # Also clear SSO session cookie
    return response


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "app": "client2", "sso_server": SSO_SERVER}


if __name__ == "__main__":
    print("Starting Client App 2 on http://localhost:8002")
    print(f"SSO Server: {SSO_SERVER}")
    uvicorn.run(app, host="0.0.0.0", port=8002)
