
"""
FastHTML Client Application 2 - JWT SSO Example
"""
from fasthtml.common import *
import jwt
import httpx
from typing import Optional
from sxcore import fprint

# JWT Configuration (must match SSO server)
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"

# SSO Configuration
SSO_SERVER = "http://localhost:8000"
CLIENT_ID = "client2"
CLIENT_SECRET = "client2_secret"
REDIRECT_URI = "http://localhost:8002/callback"

app, rt = fast_app(
    live=False,
    hdrs=(
        Link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css"),
    )
)

def verify_jwt_token(token: str) -> dict:
    """Verify JWT token locally (no server call needed!)"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        fprint('jwt_verified', f"JWT verified for {payload.get('username')}")
        return payload
    except jwt.ExpiredSignatureError:
        fprint('jwt_error', "Token expired")
        return None
    except jwt.InvalidTokenError as e:
        fprint('jwt_error', f"Invalid token: {e}")
        return None


def get_current_user(session: dict) -> Optional[dict]:
    """Get current user from FastHTML session"""
    jwt_token = session.get('jwt_token')

    if not jwt_token:
        return None

    payload = verify_jwt_token(jwt_token)

    if not payload:
        # JWT expired or invalid, clear session
        session.clear()
        return None

    return {
        'username': payload['username'],
        'email': payload.get('email'),
        'jwt_token': jwt_token
    }


@rt('/')
def get(session):
    """Home page - shows login or user info"""
    user = get_current_user(session)

    if user:
        return Main(
            Container(
                Article(
                    H1("🚀 Client Application 2"),
                    Div(
                        H3(f"Welcome, {user['username']}!"),
                        P("You are successfully authenticated via JWT SSO."),
                        H4("User Info:"),
                        Ul(
                            Li(f"Username: {user['username']}"),
                            Li(f"Email: {user['email']}"),
                            Li(f"App: Client Application 2"),
                            Li("✓ Authenticated via JWT")
                        ),
                        P(Strong("JWT Token (first 50 chars):")),
                        P(Code(user['jwt_token'][:50] + "..."), style="font-size: 0.8em; word-break: break-all;"),
                        style="background: #cfe2ff; padding: 20px; border-radius: 5px; margin: 20px 0;"
                    ),
                    Div(
                        A("Access Protected Resource", href="/protected", role="button"),
                        A("Logout", href="/logout", role="button", cls="secondary", style="margin-left: 10px;"),
                    ),
                    P(
                        "Try accessing ",
                        A("Client App 1", href="http://localhost:8001", target="_blank"),
                        " - you should be automatically logged in!",
                        style="margin-top: 40px; color: #666;"
                    )
                )
            ),
            cls="container"
        )

    # Not logged in
    return Main(
        Container(
            Article(
                H1("🚀 Client Application 2"),
                Div(
                    P("Welcome to Client Application 2. Please sign in to continue."),
                    style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;"
                ),
                A("Sign in with SSO", href="/login", role="button"),
                P(
                    "This is Client Application 2, demonstrating JWT-based SSO.",
                    style="margin-top: 40px; color: #666;"
                ),
                Div(
                    H4("SSO Magic:"),
                    Ol(
                        Li("If you already logged in to App 1, you'll auto-login here!"),
                        Li("Both apps share the same SSO session cookie"),
                        Li("JWT tokens are validated locally without server calls"),
                        Li("Logout from one app logs you out everywhere")
                    ),
                    style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px;"
                )
            )
        ),
        cls="container"
    )


@rt('/login')
def get():
    """Redirect to SSO server for authentication"""
    auth_url = f"{SSO_SERVER}/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    fprint('login', f"Redirecting to: {auth_url}")
    return RedirectResponse(url=auth_url, status_code=303)


@rt('/callback')
async def get(session, code: str):
    """Handle OAuth callback from SSO server"""
    async with httpx.AsyncClient() as client:
        try:
            # Exchange auth code for JWT access token
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
                fprint('error', f"Token exchange failed: {token_response.text}")
                return Main(
                    Container(
                        Article(
                            H2("Authentication Error"),
                            P("Failed to exchange code for token", style="color: red;"),
                            A("Try again", href="/login", role="button")
                        )
                    )
                )

            token_data = token_response.json()
            jwt_token = token_data["access_token"]

            # Verify the JWT locally (no need to call /userinfo!)
            payload = verify_jwt_token(jwt_token)

            if not payload:
                fprint('error', "Invalid JWT received from SSO server")
                return Main(
                    Container(
                        Article(
                            H2("Authentication Error"),
                            P("Invalid JWT token received", style="color: red;"),
                            A("Try again", href="/login", role="button")
                        )
                    )
                )

            # Store JWT in FastHTML session
            session['jwt_token'] = jwt_token
            session['username'] = payload['username']

            fprint('success', f"User {payload['username']} logged in successfully")

            # Redirect to home
            return RedirectResponse(url="/", status_code=303)

        except Exception as e:
            fprint('error', f"Authentication failed: {str(e)}")
            return Main(
                Container(
                    Article(
                        H2("Authentication Error"),
                        P(f"Authentication failed: {str(e)}", style="color: red;"),
                        A("Try again", href="/login", role="button")
                    )
                )
            )


@rt('/protected')
def get(session):
    """Protected resource that requires authentication"""
    user = get_current_user(session)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return Main(
        Container(
            Article(
                H1("🔒 Protected Resource"),
                Div(
                    P("This is a protected resource in Client Application 2."),
                    P("Only authenticated users can see this content."),
                    P(Strong(f"Authenticated as: {user['username']}")),
                    P(f"Email: {user['email']}"),
                    P("✓ JWT token verified locally (no server call needed!)"),
                    style="background: #d1e7dd; padding: 20px; border-radius: 5px; margin: 20px 0;"
                ),
                A("Back to Home", href="/", role="button")
            )
        ),
        cls="container"
    )


@rt('/logout')
async def get(session):
    """Logout from this application"""
    jwt_token = session.get('jwt_token')

    # Call SSO server logout to blacklist the JWT
    if jwt_token:
        async with httpx.AsyncClient() as client:
            try:
                await client.post(
                    f"{SSO_SERVER}/logout",
                    headers={"Authorization": f"Bearer {jwt_token}"}
                )
                fprint('logout', "JWT blacklisted on SSO server")
            except Exception as e:
                fprint('error', f"SSO logout failed: {e}")
                pass  # Continue logout even if SSO logout fails

    # Clear FastHTML session
    session.clear()
    fprint('logout', "Cleared FastHTML session")

    # Redirect to home
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("sso_session")  # Clear SSO server cookie if any
    return response


@rt('/health')
def get():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "app": "client2",
        "sso_server": SSO_SERVER,
        "jwt_enabled": True
    }


if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Client App 2 (FastHTML + JWT) Starting")
    print("=" * 60)
    print(f"URL: http://localhost:8002")
    print(f"SSO Server: {SSO_SERVER}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"JWT Validation: Local (no server calls!)")
    print("=" * 60)
    serve(port=8002)
