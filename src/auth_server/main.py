"""
OAuth 2.1 Authorization Server - Educational Implementation

This FastAPI application implements an OAuth 2.1 authorization server with PKCE
support for educational purposes. It demonstrates user authentication, authorization
code generation, and access token issuance following RFC 6749 and RFC 7636.

Key Features:
- OAuth 2.1 authorization code flow with mandatory PKCE
- User authentication with bcrypt password hashing
- Authorization code generation with 10-minute expiration
- Access token issuance after PKCE verification
- Comprehensive logging for educational purposes
- Demo user accounts for testing

Security Features:
- PKCE (Proof Key for Code Exchange) mandatory for all flows
- Short-lived authorization codes (10 minutes)
- Secure token generation using cryptographic randomness
- Input validation and sanitization
- Security headers for web protection
"""

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from .routes import authorize_endpoint, login_endpoint, token_endpoint
from ..shared.oauth_models import TokenRequest, TokenResponse
from ..shared.logging_utils import OAuthLogger
from ..shared.security import SecurityHeaders
import os

# Initialize logger
logger = OAuthLogger("AUTH-SERVER")

# Create FastAPI app with comprehensive metadata
app = FastAPI(
    title="OAuth 2.1 Authorization Server",
    description="""
    Educational OAuth 2.1 Authorization Server Implementation

    This server demonstrates the authorization server role in OAuth 2.1 flows:

    **Key Endpoints:**
    - `/authorize` - Authorization endpoint for OAuth flow initiation
    - `/token` - Token endpoint for authorization code exchange
    - `/login` - User authentication endpoint
    - `/health` - Health check endpoint

    **Security Features:**
    - Mandatory PKCE (Proof Key for Code Exchange)
    - bcrypt password hashing for user credentials
    - Short-lived authorization codes (10 minutes)
    - Comprehensive input validation
    - Detailed security logging

    **Demo Accounts:**
    - alice / password123
    - bob / secret456
    - carol / mypass789
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "OAuth 2.1 Learning Project",
        "url": "https://github.com/oauth-learning/python-oauth-learning",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Configure Jinja2 templates for login forms
templates = Jinja2Templates(directory="src/auth_server/templates")

# Add CORS middleware to allow cross-origin requests from client and resource server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",  # Client application
        "http://localhost:8082",  # Resource server
        "http://127.0.0.1:8080",  # Alternative localhost format
        "http://127.0.0.1:8082"   # Alternative localhost format
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# Security headers middleware for web protection
@app.middleware("http")
async def add_security_headers(request, call_next):
    """
    Add security headers to all HTTP responses.

    This middleware adds standard security headers to protect against
    common web vulnerabilities like XSS, clickjacking, and MIME sniffing.
    """
    response = await call_next(request)

    # Get OAuth-specific security headers
    security_headers = SecurityHeaders.get_oauth_security_headers()

    # Apply headers to response
    for header_name, header_value in security_headers.items():
        response.headers[header_name] = header_value

    # Log security headers application for educational purposes
    if request.url.path not in ["/health", "/docs", "/redoc"]:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Security Headers Applied",
            {
                "path": str(request.url.path),
                "headers_applied": list(security_headers.keys()),
                "client_ip": request.client.host if request.client else "unknown"
            }
        )

    return response

# Health check endpoint for monitoring and startup verification
@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring server status.

    This endpoint is used by:
    - Load balancers for health monitoring
    - Startup scripts to verify server readiness
    - Monitoring systems for service availability

    Returns:
        JSONResponse: Server health status and metadata
    """
    logger.log_oauth_message(
        "SYSTEM", "AUTH-SERVER",
        "Health Check Request",
        {
            "status": "healthy",
            "service": "authorization-server",
            "endpoints_available": ["/authorize", "/token", "/login", "/health"]
        }
    )

    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "OAuth 2.1 Authorization Server",
            "version": "1.0.0",
            "endpoints": {
                "authorize": "/authorize",
                "token": "/token",
                "login": "/login",
                "health": "/health"
            },
            "features": [
                "OAuth 2.1 Authorization Code Flow",
                "PKCE (Proof Key for Code Exchange)",
                "bcrypt Password Hashing",
                "Demo User Accounts"
            ]
        }
    )

# OAuth 2.1 Authorization Endpoints

@app.get("/authorize",
         summary="OAuth 2.1 Authorization Endpoint",
         description="""
         Initiate OAuth 2.1 authorization code flow with PKCE.

         This endpoint validates the authorization request and presents
         a login form to the user for authentication and consent.

         **Required Parameters:**
         - client_id: OAuth client identifier
         - redirect_uri: Client callback URL
         - scope: Requested permissions
         - state: CSRF protection parameter
         - code_challenge: PKCE challenge
         - code_challenge_method: Must be 'S256'
         - response_type: Must be 'code'
         """)
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    response_type: str = "code"
):
    """OAuth 2.1 authorization endpoint with PKCE validation."""
    return await authorize_endpoint(
        request, client_id, redirect_uri, scope, state,
        code_challenge, code_challenge_method, response_type
    )

@app.post("/login",
          summary="User Authentication Endpoint",
          description="""
          Process user login and generate authorization code.

          This endpoint authenticates the user credentials and,
          if successful, generates an authorization code tied to
          the PKCE challenge for secure token exchange.

          **Demo Accounts:**
          - alice / password123
          - bob / secret456
          - carol / mypass789
          """)
async def login(
    request: Request,
    username: str = Form(..., description="Username for authentication"),
    password: str = Form(..., description="Password for authentication"),
    client_id: str = Form(..., description="OAuth client identifier"),
    redirect_uri: str = Form(..., description="Client callback URL"),
    scope: str = Form(..., description="Requested permissions"),
    state: str = Form(..., description="CSRF protection parameter"),
    code_challenge: str = Form(..., description="PKCE challenge"),
    code_challenge_method: str = Form(..., description="PKCE method (S256)"),
    response_type: str = Form(..., description="OAuth response type (code)")
):
    """Process user authentication and generate authorization code."""
    return await login_endpoint(
        request, username, password, client_id, redirect_uri,
        scope, state, code_challenge, code_challenge_method, response_type
    )

@app.post("/token",
          response_model=TokenResponse,
          summary="OAuth 2.1 Token Exchange Endpoint",
          description="""
          Exchange authorization code + PKCE verifier for access token.

          This endpoint validates the authorization code and PKCE verifier,
          then issues an access token that can be used to access protected
          resources on the resource server.

          **Security Features:**
          - PKCE verification prevents code interception attacks
          - One-time use authorization codes
          - Short-lived tokens (1 hour default)
          """)
async def token(
    grant_type: str = Form(..., description="OAuth grant type (authorization_code)"),
    code: str = Form(..., description="Authorization code from /authorize"),
    redirect_uri: str = Form(..., description="Client callback URL"),
    client_id: str = Form(..., description="OAuth client identifier"),
    code_verifier: str = Form(..., description="PKCE code verifier")
):
    """Exchange authorization code for access token with PKCE verification.

    RFC 6749 section 4.1.3 requires the token endpoint to accept
    application/x-www-form-urlencoded, so the parameters are declared as form
    fields and assembled into a TokenRequest for validation.
    """
    try:
        token_request = TokenRequest(
            grant_type=grant_type,
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            code_verifier=code_verifier
        )
    except ValidationError as exc:
        # RFC 6749 section 5.2: malformed token requests are 400 invalid_request,
        # not FastAPI's default 422.
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Invalid token request parameters: {exc.error_count()} error(s)"
            }
        )

    return await token_endpoint(token_request)

# Root endpoint with comprehensive service information
@app.get("/",
         summary="Authorization Server Information",
         description="Get information about the OAuth 2.1 authorization server and available endpoints.")
async def root():
    """
    Root endpoint providing OAuth 2.1 authorization server information.

    Returns comprehensive information about the server capabilities,
    available endpoints, and OAuth flow documentation.

    Returns:
        JSONResponse: Server information and endpoint documentation
    """
    logger.log_oauth_message(
        "CLIENT", "AUTH-SERVER",
        "Service Information Request",
        {
            "endpoint": "/",
            "method": "GET",
            "service": "authorization-server"
        }
    )

    return JSONResponse(
        content={
            "service": "OAuth 2.1 Authorization Server",
            "description": "Educational OAuth 2.1 implementation with PKCE support",
            "version": "1.0.0",
            "oauth_version": "2.1",
            "supported_flows": ["authorization_code"],
            "security_features": [
                "PKCE (Proof Key for Code Exchange)",
                "bcrypt password hashing",
                "Short-lived authorization codes",
                "Secure token generation"
            ],
            "endpoints": {
                "authorization": {
                    "url": "/authorize",
                    "method": "GET",
                    "description": "OAuth 2.1 authorization endpoint"
                },
                "token": {
                    "url": "/token",
                    "method": "POST",
                    "description": "Token exchange endpoint"
                },
                "login": {
                    "url": "/login",
                    "method": "POST",
                    "description": "User authentication endpoint"
                },
                "health": {
                    "url": "/health",
                    "method": "GET",
                    "description": "Health check endpoint"
                }
            },
            "demo_accounts": [
                {"username": "alice", "password": "password123"},
                {"username": "bob", "password": "secret456"},
                {"username": "carol", "password": "mypass789"}
            ],
            "documentation": {
                "interactive_docs": "/docs",
                "redoc": "/redoc"
            }
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)