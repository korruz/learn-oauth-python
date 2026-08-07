"""
OAuth 2.1 Learning Client Application

This FastAPI application demonstrates the client side of the OAuth 2.1 flow,
including PKCE implementation and session management for educational purposes.
"""

from fastapi import FastAPI, Request, Response, HTTPException, Form
from typing import Optional
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import urlencode
import secrets
import os
from pathlib import Path
import httpx

# Import shared utilities
from ..shared.oauth_models import AuthorizationRequest, TokenRequest, TokenResponse
from ..shared.crypto_utils import PKCEGenerator
from ..shared.logging_utils import OAuthLogger

# Initialize FastAPI app
app = FastAPI(
    title="OAuth 2.1 Learning Client",
    description="Educational OAuth 2.1 client implementation demonstrating PKCE flow",
    version="1.0.0"
)

# Add session middleware for PKCE storage
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
)

# Configure templates and static files
templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(templates_dir))
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Initialize logger
logger = OAuthLogger("CLIENT")

# OAuth configuration
OAUTH_CONFIG = {
    "client_id": "demo-client",
    "authorization_server": "http://localhost:8081",
    "resource_server": "http://localhost:8082",
    "redirect_uri": "http://localhost:8080/callback",
    "scope": "read"
}

@app.get("/", response_class=HTMLResponse)
async def start_oauth_flow(request: Request):
    """
    Start the OAuth 2.1 flow by generating PKCE challenge and displaying start page.

    This endpoint demonstrates:
    - PKCE challenge generation
    - Authorization URL construction
    - Session management for security parameters
    """
    # Generate PKCE challenge and verifier
    verifier, challenge = PKCEGenerator.generate_challenge()

    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(16)

    # Store PKCE verifier and state in session
    request.session["pkce_verifier"] = verifier
    request.session["state"] = state

    # Build authorization URL with all required parameters
    auth_params = {
        "client_id": OAUTH_CONFIG["client_id"],
        "redirect_uri": OAUTH_CONFIG["redirect_uri"],
        "scope": OAUTH_CONFIG["scope"],
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_type": "code"
    }

    authorization_url = f"{OAUTH_CONFIG['authorization_server']}/authorize?{urlencode(auth_params)}"

    # Log the OAuth flow initiation
    logger.log_oauth_message(
        "CLIENT", "USER-BROWSER",
        "OAuth Flow Initiation",
        {
            "client_id": OAUTH_CONFIG["client_id"],
            "redirect_uri": OAUTH_CONFIG["redirect_uri"],
            "scope": OAUTH_CONFIG["scope"],
            "state": state,
            "pkce_challenge": challenge[:10] + "...",
            "pkce_method": "S256",
            "authorization_url": authorization_url
        }
    )

    return templates.TemplateResponse(request, "start_flow.html", {
        "authorization_url": authorization_url,
        "client_id": OAUTH_CONFIG["client_id"],
        "redirect_uri": OAUTH_CONFIG["redirect_uri"],
        "scope": OAUTH_CONFIG["scope"],
        "state": state,
        "pkce_challenge": challenge,
        "pkce_verifier": verifier[:10] + "..." + verifier[-10:],  # Show partial for education
        "auth_server": OAUTH_CONFIG["authorization_server"]
    })

@app.get("/callback", response_class=HTMLResponse)
async def oauth_callback(request: Request, code: Optional[str] = None,
                        error: Optional[str] = None, state: Optional[str] = None):
    """
    Handle OAuth authorization callback from the authorization server.

    This endpoint demonstrates:
    - Authorization code processing
    - State parameter validation for CSRF protection
    - Error handling for OAuth error responses
    - Session management for received authorization code
    """

    # Log the callback reception
    logger.log_oauth_message(
        "AUTH-SERVER", "CLIENT",
        "Authorization Callback Received",
        {
            "code": code[:10] + "..." if code else None,
            "state": state,
            "error": error,
            "error_description": request.query_params.get("error_description")
        }
    )

    # Handle OAuth errors
    if error:
        error_description = request.query_params.get("error_description", "No description provided")

        logger.log_oauth_message(
            "CLIENT", "CLIENT",
            "OAuth Error Received",
            {
                "error": error,
                "error_description": error_description,
                "state": state
            }
        )

        return templates.TemplateResponse(request, "error.html", {
            "error": error,
            "error_description": error_description,
            "state": state
        })

    # Validate required parameters
    if not code:
        raise HTTPException(400, "Missing authorization code")

    if not state:
        raise HTTPException(400, "Missing state parameter")

    # Validate state parameter (CSRF protection)
    session_state = request.session.get("state")
    if not session_state or session_state != state:
        logger.log_oauth_message(
            "CLIENT", "CLIENT",
            "State Validation Failed",
            {
                "received_state": state,
                "expected_state": session_state,
                "security_risk": "Possible CSRF attack"
            }
        )

        return templates.TemplateResponse(request, "error.html", {
            "error": "invalid_state",
            "error_description": "State parameter validation failed. Possible CSRF attack.",
            "state": state
        })

    # Store authorization code in session for token exchange
    request.session["authorization_code"] = code

    logger.log_oauth_message(
        "CLIENT", "CLIENT",
        "Authorization Code Stored",
        {
            "code": code[:10] + "...",
            "state_validated": True,
            "next_step": "token_exchange"
        }
    )

    return templates.TemplateResponse(request, "callback.html", {
        "code": code,
        "state": state,
        "code_preview": code[:20] + "..." + code[-10:] if len(code) > 30 else code
    })

@app.get("/exchange-token", response_class=HTMLResponse)
async def exchange_token(request: Request):
    """
    Exchange authorization code + PKCE verifier for access token.

    This endpoint demonstrates:
    - Token exchange request construction
    - PKCE verifier inclusion for security
    - HTTP client usage for server-to-server communication
    - Token response processing and storage
    """

    # Retrieve stored values from session
    authorization_code = request.session.get("authorization_code")
    pkce_verifier = request.session.get("pkce_verifier")

    if not authorization_code:
        return templates.TemplateResponse(request, "error.html", {
            "error": "missing_code",
            "error_description": "No authorization code found in session. Please restart the OAuth flow."
        })

    if not pkce_verifier:
        return templates.TemplateResponse(request, "error.html", {
            "error": "missing_verifier",
            "error_description": "No PKCE verifier found in session. Please restart the OAuth flow."
        })

    # Prepare token exchange request
    token_request_data = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": OAUTH_CONFIG["redirect_uri"],
        "client_id": OAUTH_CONFIG["client_id"],
        "code_verifier": pkce_verifier
    }

    logger.log_oauth_message(
        "CLIENT", "AUTH-SERVER",
        "Token Exchange Request",
        {
            "grant_type": "authorization_code",
            "code": authorization_code[:10] + "...",
            "redirect_uri": OAUTH_CONFIG["redirect_uri"],
            "client_id": OAUTH_CONFIG["client_id"],
            "code_verifier": pkce_verifier[:10] + "...",
            "endpoint": f"{OAUTH_CONFIG['authorization_server']}/token"
        }
    )

    # Make token exchange request
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OAUTH_CONFIG['authorization_server']}/token",
                data=token_request_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code == 200:
                token_data = response.json()

                # Store access token in session
                request.session["access_token"] = token_data["access_token"]
                request.session["token_type"] = token_data.get("token_type", "Bearer")
                request.session["expires_in"] = token_data.get("expires_in", 3600)
                request.session["scope"] = token_data.get("scope", OAUTH_CONFIG["scope"])

                logger.log_oauth_message(
                    "AUTH-SERVER", "CLIENT",
                    "Token Exchange Success",
                    {
                        "access_token": token_data["access_token"][:10] + "...",
                        "token_type": token_data.get("token_type", "Bearer"),
                        "expires_in": token_data.get("expires_in", 3600),
                        "scope": token_data.get("scope", OAUTH_CONFIG["scope"])
                    }
                )

                return templates.TemplateResponse(request, "token_success.html", {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "scope": token_data.get("scope", OAUTH_CONFIG["scope"]),
                    "token_preview": token_data["access_token"][:20] + "..." + token_data["access_token"][-10:]
                })
            else:
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}

                logger.log_oauth_message(
                    "AUTH-SERVER", "CLIENT",
                    "Token Exchange Failed",
                    {
                        "status_code": response.status_code,
                        "error": error_data.get("error", "unknown_error"),
                        "error_description": error_data.get("error_description", "Token exchange failed")
                    }
                )

                return templates.TemplateResponse(request, "error.html", {
                    "error": error_data.get("error", "token_exchange_failed"),
                    "error_description": error_data.get("error_description", f"Token exchange failed with status {response.status_code}")
                })

    except Exception as e:
        logger.log_oauth_message(
            "CLIENT", "CLIENT",
            "Token Exchange Error",
            {
                "error": "network_error",
                "error_description": str(e),
                "auth_server": OAUTH_CONFIG["authorization_server"]
            }
        )

        return templates.TemplateResponse(request, "error.html", {
            "error": "network_error",
            "error_description": f"Failed to connect to authorization server: {str(e)}"
        })

@app.get("/access-resource", response_class=HTMLResponse)
async def access_protected_resource(request: Request):
    """
    Access protected resource using the Bearer token.

    This endpoint demonstrates:
    - Bearer token inclusion in Authorization headers
    - Protected resource request to resource server
    - Response handling and display
    """

    # Retrieve access token from session
    access_token = request.session.get("access_token")
    token_type = request.session.get("token_type", "Bearer")

    if not access_token:
        return templates.TemplateResponse(request, "error.html", {
            "error": "missing_token",
            "error_description": "No access token found in session. Please complete the OAuth flow first."
        })

    # Prepare authorization header
    auth_header = f"{token_type} {access_token}"

    logger.log_oauth_message(
        "CLIENT", "RESOURCE-SERVER",
        "Protected Resource Request",
        {
            "endpoint": f"{OAUTH_CONFIG['resource_server']}/protected",
            "method": "GET",
            "authorization": f"{token_type} {access_token[:10]}...",
            "resource_server": OAUTH_CONFIG["resource_server"]
        }
    )

    # Make request to protected resource
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{OAUTH_CONFIG['resource_server']}/protected",
                headers={"Authorization": auth_header}
            )

            if response.status_code == 200:
                resource_content = response.text

                logger.log_oauth_message(
                    "RESOURCE-SERVER", "CLIENT",
                    "Protected Resource Response",
                    {
                        "status_code": 200,
                        "content_length": len(resource_content),
                        "content_type": response.headers.get("content-type", "text/plain")
                    }
                )

                return templates.TemplateResponse(request, "resource_success.html", {
                    "resource_content": resource_content,
                    "token_used": access_token[:20] + "..." + access_token[-10:],
                    "resource_url": f"{OAUTH_CONFIG['resource_server']}/protected"
                })
            else:
                error_msg = response.text if response.text else f"HTTP {response.status_code}"

                logger.log_oauth_message(
                    "RESOURCE-SERVER", "CLIENT",
                    "Protected Resource Access Failed",
                    {
                        "status_code": response.status_code,
                        "error": error_msg,
                        "token_valid": False
                    }
                )

                return templates.TemplateResponse(request, "error.html", {
                    "error": "resource_access_failed",
                    "error_description": f"Failed to access protected resource: {error_msg}"
                })

    except Exception as e:
        logger.log_oauth_message(
            "CLIENT", "CLIENT",
            "Resource Access Error",
            {
                "error": "network_error",
                "error_description": str(e),
                "resource_server": OAUTH_CONFIG["resource_server"]
            }
        )

        return templates.TemplateResponse(request, "error.html", {
            "error": "network_error",
            "error_description": f"Failed to connect to resource server: {str(e)}"
        })

@app.get("/user-info", response_class=HTMLResponse)
async def get_user_info(request: Request):
    """
    Get user information from the resource server using the Bearer token.

    This endpoint demonstrates:
    - User info endpoint access
    - Bearer token authentication
    - JSON response handling
    """

    # Retrieve access token from session
    access_token = request.session.get("access_token")
    token_type = request.session.get("token_type", "Bearer")

    if not access_token:
        return templates.TemplateResponse(request, "error.html", {
            "error": "missing_token",
            "error_description": "No access token found in session. Please complete the OAuth flow first."
        })

    # Prepare authorization header
    auth_header = f"{token_type} {access_token}"

    logger.log_oauth_message(
        "CLIENT", "RESOURCE-SERVER",
        "User Info Request",
        {
            "endpoint": f"{OAUTH_CONFIG['resource_server']}/userinfo",
            "method": "GET",
            "authorization": f"{token_type} {access_token[:10]}...",
            "resource_server": OAUTH_CONFIG["resource_server"]
        }
    )

    # Make request to user info endpoint
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{OAUTH_CONFIG['resource_server']}/userinfo",
                headers={"Authorization": auth_header}
            )

            if response.status_code == 200:
                try:
                    user_info = response.json()
                except:
                    user_info = {"info": response.text}

                logger.log_oauth_message(
                    "RESOURCE-SERVER", "CLIENT",
                    "User Info Response",
                    {
                        "status_code": 200,
                        "user_data": user_info
                    }
                )

                return templates.TemplateResponse(request, "user_info.html", {
                    "user_info": user_info,
                    "token_used": access_token[:20] + "..." + access_token[-10:],
                    "userinfo_url": f"{OAUTH_CONFIG['resource_server']}/userinfo"
                })
            else:
                error_msg = response.text if response.text else f"HTTP {response.status_code}"

                logger.log_oauth_message(
                    "RESOURCE-SERVER", "CLIENT",
                    "User Info Access Failed",
                    {
                        "status_code": response.status_code,
                        "error": error_msg
                    }
                )

                return templates.TemplateResponse(request, "error.html", {
                    "error": "userinfo_access_failed",
                    "error_description": f"Failed to access user info: {error_msg}"
                })

    except Exception as e:
        logger.log_oauth_message(
            "CLIENT", "CLIENT",
            "User Info Error",
            {
                "error": "network_error",
                "error_description": str(e),
                "resource_server": OAUTH_CONFIG["resource_server"]
            }
        )

        return templates.TemplateResponse(request, "error.html", {
            "error": "network_error",
            "error_description": f"Failed to connect to resource server: {str(e)}"
        })

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "oauth-client"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)