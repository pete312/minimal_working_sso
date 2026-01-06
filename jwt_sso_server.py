
"""
JWT SSO Server - Single Sign-On server using JWT tokens and FastHTML
"""
from fasthtml.common import *
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass
from sxcore import fprint

# JWT Configuration
SECRET_KEY = "your-secret-key-change-in-production"  # Shared secret for JWT signing
ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

app, rt = fast_app(
    live=False,
    hdrs=(
        Link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css"),
    )
)

# In-memory storage
users_db = {
    "alice": hashlib.sha256("password123".encode()).hexdigest(),
    "bob": hashlib.sha256("password456".encode()).hexdigest(),
}

# Store auth codes temporarily (still needed for OAuth flow)
auth_codes = {}

# Registered client applications
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

# JWT blacklist for logout (in production, use Redis with TTL)
jwt_blacklist = set()


def create_jwt_token(username: str, email: str = None) -> str:
    """Create a JWT token with user information"""
    payload = {
        'username': username,
        'email': email or f"{username}@example.com",
        'iat': datetime.utcnow(),  # Issued at
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)  # Expiration
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    fprint('jwt_created', f"Created JWT for {username}, expires in {JWT_EXPIRATION_HOURS}h")
    return token


def verify_jwt_token(token: str) -> dict:
    """Verify and decode a JWT token"""
    try:
        # Check if token is blacklisted
        if token in jwt_blacklist:
            fprint('jwt_error', "Token is blacklisted")
            return None

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        fprint('jwt_verified', f"JWT verified for {payload.get('username')}")
        return payload
    except jwt.ExpiredSignatureError:
        fprint('jwt_error', "Token expired")
        return None
    except jwt.InvalidTokenError as e:
        fprint('jwt_error', f"Invalid token: {e}")
        return None


@rt('/')
def get():
    """Home page - API info"""
    return Main(
        Container(
            H1("🔐 JWT SSO Server"),
            Article(
                H3("SSO Server is Running"),
                P("This is a JWT-based Single Sign-On server using FastHTML"),
                H4("Available Endpoints:"),
                Ul(
                    Li(Code("/login"), " - Login page"),
                    Li(Code("/authorize"), " - OAuth2 authorization"),
                    Li(Code("/token"), " - Token exchange (POST)"),
                    Li(Code("/userinfo"), " - Get user info from JWT"),
                    Li(Code("/logout"), " - Logout and blacklist JWT"),
                ),
                H4("Test Users:"),
                Ul(
                    Li("alice / password123"),
                    Li("bob / password456"),
                ),
                H4("Registered Clients:"),
                Ul(
                    Li("client1 (localhost:8001)"),
                    Li("client2 (localhost:8002)"),
                )
            )
        ),
        cls="container"
    )


@rt('/login')
def get(redirect_uri: str = None, client_id: str = None):
    """Display login form"""
    return Main(
        Container(
            Article(
                H2("Single Sign-On Login"),
                Form(
                    Div(
                        Label("Username", For="username"),
                        Input(type="text", name="username", id="username", required=True, placeholder="alice or bob"),
                        Small("Try: alice or bob")
                    ),
                    Div(
                        Label("Password", For="password"),
                        Input(type="password", name="password", id="password", required=True),
                        Small("alice: password123, bob: password456")
                    ),
                    Input(type="hidden", name="redirect_uri", value=redirect_uri or ""),
                    Input(type="hidden", name="client_id", value=client_id or ""),
                    Button("Sign In", type="submit"),
                    method="post",
                    action="/login"
                )
            )
        ),
        cls="container"
    )


@rt('/login')
def post(username: str, password: str, redirect_uri: str = None, client_id: str = None, sso_session: str = None):
    """Process login and create JWT"""
    if not username or not password:
        return Main(
            Container(
                Article(
                    H2("Login Error"),
                    P("Username and password are required", style="color: red;"),
                    A("Try again", href="/login")
                )
            )
        )

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username not in users_db or users_db[username] != password_hash:
        return Main(
            Container(
                Article(
                    H2("Login Error"),
                    P("Invalid credentials", style="color: red;"),
                    A("Try again", href="/login")
                )
            )
        )

    # Create JWT token
    jwt_token = create_jwt_token(username, f"{username}@example.com")

    # If OAuth flow, create auth code
    if redirect_uri and client_id:
        auth_code = secrets.token_urlsafe(32)
        auth_codes[auth_code] = {
            "username": username,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=5)
        }

        # Redirect with auth code and set JWT cookie
        response = RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=303)
        response.set_cookie(
            key="sso_session",
            value=jwt_token,
            httponly=True,
            max_age=86400,  # 24 hours
            samesite="lax"
        )
        return response

    # Direct login (no OAuth flow)
    return Main(
        Container(
            Article(
                H2("Login Successful"),
                P(f"Welcome, {username}!"),
                P(f"JWT Token: {jwt_token[:50]}..."),
                A("Home", href="/")
            )
        )
    )


@rt('/authorize')
def get(client_id: str, redirect_uri: str, response_type: str = "code", sso_session: str = None):
    """OAuth2-style authorization endpoint"""
    if client_id not in registered_clients:
        return Main(
            Container(
                Article(
                    H2("Authorization Error"),
                    P("Invalid client_id", style="color: red;")
                )
            )
        )

    if registered_clients[client_id]["redirect_uri"] != redirect_uri:
        return Main(
            Container(
                Article(
                    H2("Authorization Error"),
                    P("Invalid redirect_uri", style="color: red;")
                )
            )
        )

    # Check if user has valid JWT session
    if sso_session:
        payload = verify_jwt_token(sso_session)
        if payload:
            # User already logged in, create auth code
            auth_code = secrets.token_urlsafe(32)
            auth_codes[auth_code] = {
                "username": payload["username"],
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=5)
            }
            return RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=303)

    # No valid session, redirect to login
    return RedirectResponse(
        url=f"/login?redirect_uri={redirect_uri}&client_id={client_id}",
        status_code=303
    )


@rt('/token')
def post(code: str, client_id: str, client_secret: str, redirect_uri: str):
    """Exchange authorization code for JWT access token"""
    if code not in auth_codes:
        return {"error": "invalid_grant", "error_description": "Invalid authorization code"}, 400

    auth_data = auth_codes[code]

    if auth_data["expires_at"] < datetime.now():
        del auth_codes[code]
        return {"error": "invalid_grant", "error_description": "Authorization code expired"}, 400

    if auth_data["client_id"] != client_id:
        return {"error": "invalid_client", "error_description": "Client ID mismatch"}, 400

    if client_id not in registered_clients:
        return {"error": "invalid_client", "error_description": "Invalid client"}, 400

    if registered_clients[client_id]["secret"] != client_secret:
        return {"error": "invalid_client", "error_description": "Invalid client secret"}, 401

    if auth_data["redirect_uri"] != redirect_uri:
        return {"error": "invalid_grant", "error_description": "Redirect URI mismatch"}, 400

    # Create JWT access token
    username = auth_data["username"]
    access_token = create_jwt_token(username, f"{username}@example.com")

    # Delete used auth code
    del auth_codes[code]

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "username": username
    }


@rt('/userinfo')
def get(request):
    """Get user information from JWT token"""
    authorization = request.headers.get("authorization")
    fprint('auth_header', f"Authorization: {authorization}")

    if not authorization or not authorization.startswith("Bearer "):
        fprint('error', "Missing or invalid auth header")
        return {"error": "unauthorized", "error_description": "Missing or invalid authorization header"}, 401

    token = authorization.replace("Bearer ", "")

    payload = verify_jwt_token(token)
    if not payload:
        return {"error": "unauthorized", "error_description": "Invalid or expired token"}, 401

    return {
        "username": payload["username"],
        "email": payload.get("email"),
        "authenticated": True,
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp")
    }


@rt('/logout')
def post(request, sso_session: str = None):
    """Logout - blacklist the JWT token"""
    username = None

    # Check for Bearer token in Authorization header
    authorization = request.headers.get("authorization")
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        payload = verify_jwt_token(token)
        if payload:
            username = payload.get("username")
            # Add to blacklist
            jwt_blacklist.add(token)
            fprint('logout', f"Blacklisted JWT for {username}")

    # Also check for SSO session cookie
    if sso_session:
        payload = verify_jwt_token(sso_session)
        if payload:
            username = username or payload.get("username")
            jwt_blacklist.add(sso_session)
            fprint('logout', f"Blacklisted SSO session JWT for {username}")

    response = Response('{"status": "logged out"}', media_type="application/json")
    response.delete_cookie("sso_session")
    return response


if __name__ == "__main__":
    print("=" * 60)
    print("🔐 JWT SSO Server Starting")
    print("=" * 60)
    print(f"URL: http://localhost:8000")
    print(f"JWT Secret: {SECRET_KEY}")
    print(f"Algorithm: {ALGORITHM}")
    print(f"Token Expiration: {JWT_EXPIRATION_HOURS} hours")
    print()
    print("Registered Users:")
    print("  - alice / password123")
    print("  - bob / password456")
    print()
    print("Registered Clients:")
    print("  - client1 (http://localhost:8001)")
    print("  - client2 (http://localhost:8002)")
    print("=" * 60)
    serve(port=8000)
