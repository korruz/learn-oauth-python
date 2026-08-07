from fastapi import Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import urlencode
from typing import Optional

from ..shared.oauth_models import AuthorizationRequest, TokenRequest, TokenResponse
from ..shared.crypto_utils import PKCEGenerator
from ..shared.logging_utils import OAuthLogger
from .storage import UserStore, AuthCodeStore

# Initialize components
templates = Jinja2Templates(directory="src/auth_server/templates")
logger = OAuthLogger("AUTH-SERVER")
user_store = UserStore()
auth_code_store = AuthCodeStore()


async def authorize_endpoint(
    request: Request,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    response_type: str = "code"
):
    """OAuth 2.1 authorization endpoint with parameter validation"""

    # Log incoming authorization request
    logger.log_oauth_message(
        "CLIENT", "AUTH-SERVER",
        "Authorization Request Received",
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge[:20] + "..." if len(code_challenge) > 20 else code_challenge,
            "code_challenge_method": code_challenge_method,
            "response_type": response_type
        }
    )

    # Validate response_type
    if response_type != "code":
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Authorization Request Validation Failed",
            {
                "error": "unsupported_response_type",
                "description": f"Only 'code' response type supported, got '{response_type}'"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_response_type",
                "error_description": "Only 'code' response type is supported"
            }
        )

    # Validate PKCE method
    if code_challenge_method != "S256":
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Authorization Request Validation Failed",
            {
                "error": "invalid_request",
                "description": f"Only 'S256' PKCE method supported, got '{code_challenge_method}'"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Only 'S256' PKCE method is supported"
            }
        )

    # Validate client_id (simple validation for demo)
    if not client_id or client_id != "demo-client":
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Authorization Request Validation Failed",
            {
                "error": "invalid_client",
                "description": f"Unknown client_id: {client_id}"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Invalid client_id"
            }
        )

    # Validate redirect_uri (simple validation for demo)
    allowed_redirect_uris = [
        "http://localhost:8080/callback",
        "http://127.0.0.1:8080/callback"
    ]
    if redirect_uri not in allowed_redirect_uris:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Authorization Request Validation Failed",
            {
                "error": "invalid_request",
                "description": f"Invalid redirect_uri: {redirect_uri}"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Invalid redirect_uri"
            }
        )

    # Validate code_challenge
    if not code_challenge or len(code_challenge) < 43:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Authorization Request Validation Failed",
            {
                "error": "invalid_request",
                "description": "Invalid code_challenge format"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Invalid code_challenge"
            }
        )

    # Create authorization request object
    auth_request = AuthorizationRequest(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        response_type=response_type
    )

    logger.log_oauth_message(
        "AUTH-SERVER", "AUTH-SERVER",
        "Authorization Request Validated Successfully",
        {
            "client_id": client_id,
            "scope": scope,
            "pkce_method": code_challenge_method,
            "next_step": "user_authentication"
        }
    )

    # Display login form with demo accounts
    return templates.TemplateResponse(request, "login.html", {
        "auth_request": auth_request,
        "demo_accounts": user_store.get_demo_accounts()
    })


async def login_endpoint(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
    response_type: str = Form(...)
):
    """Process user login and generate authorization code"""

    logger.log_oauth_message(
        "USER-BROWSER", "AUTH-SERVER",
        "User Login Attempt",
        {
            "username": username,
            "client_id": client_id,
            "scope": scope
        }
    )

    # Authenticate user
    user = user_store.authenticate(username, password)
    if not user:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "User Authentication Failed",
            {
                "username": username,
                "reason": "invalid_credentials"
            }
        )

        # Recreate auth request for error display
        auth_request = AuthorizationRequest(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            response_type=response_type
        )

        return templates.TemplateResponse(request, "login.html", {
            "auth_request": auth_request,
            "demo_accounts": user_store.get_demo_accounts(),
            "error": "Invalid username or password"
        })

    logger.log_oauth_message(
        "AUTH-SERVER", "AUTH-SERVER",
        "User Authentication Successful",
        {
            "username": username,
            "user_email": user['email'],
            "user_name": user['name']
        }
    )

    # Generate authorization code
    auth_code = auth_code_store.store_code(
        client_id=client_id,
        user_id=username,
        scope=scope,
        code_challenge=code_challenge,
        redirect_uri=redirect_uri
    )

    logger.log_oauth_message(
        "AUTH-SERVER", "AUTH-SERVER",
        "Authorization Code Generated",
        {
            "code": auth_code[:10] + "...",
            "user_id": username,
            "client_id": client_id,
            "scope": scope,
            "expires_in_minutes": 10,
            "pkce_challenge": code_challenge[:20] + "..."
        }
    )

    # Build redirect URL with authorization code
    callback_params = {
        "code": auth_code,
        "state": state
    }

    callback_url = f"{redirect_uri}?{urlencode(callback_params)}"

    logger.log_oauth_message(
        "AUTH-SERVER", "CLIENT",
        "Authorization Code Response",
        {
            "redirect_uri": redirect_uri,
            "code": auth_code[:10] + "...",
            "state": state,
            "callback_url": callback_url
        }
    )

    return RedirectResponse(url=callback_url, status_code=302)


async def token_endpoint(token_request: TokenRequest):
    """OAuth 2.1 token exchange endpoint with PKCE verification"""

    logger.log_oauth_message(
        "CLIENT", "AUTH-SERVER",
        "Token Exchange Request",
        {
            "grant_type": token_request.grant_type,
            "client_id": token_request.client_id,
            "redirect_uri": str(token_request.redirect_uri),
            "code": token_request.code[:10] + "...",
            "code_verifier": token_request.code_verifier[:10] + "..."
        }
    )

    # Validate grant type
    if token_request.grant_type != "authorization_code":
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Token Exchange Validation Failed",
            {
                "error": "unsupported_grant_type",
                "description": f"Only 'authorization_code' grant type supported, got '{token_request.grant_type}'"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_grant_type",
                "error_description": "Only 'authorization_code' grant type is supported"
            }
        )

    # Retrieve and validate authorization code
    auth_code_data = auth_code_store.get_code(token_request.code)
    if not auth_code_data:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Token Exchange Validation Failed",
            {
                "error": "invalid_grant",
                "description": "Invalid, expired, or already used authorization code"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_grant",
                "error_description": "Invalid authorization code"
            }
        )

    # Validate client_id matches
    if token_request.client_id != auth_code_data['client_id']:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Token Exchange Validation Failed",
            {
                "error": "invalid_client",
                "description": f"Client ID mismatch: expected {auth_code_data['client_id']}, got {token_request.client_id}"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client ID mismatch"
            }
        )

    # Validate redirect_uri matches
    if str(token_request.redirect_uri) != auth_code_data['redirect_uri']:
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "Token Exchange Validation Failed",
            {
                "error": "invalid_grant",
                "description": f"Redirect URI mismatch: expected {auth_code_data['redirect_uri']}, got {token_request.redirect_uri}"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_grant",
                "error_description": "Redirect URI mismatch"
            }
        )

    # Verify PKCE challenge
    if not PKCEGenerator.verify_challenge(token_request.code_verifier, auth_code_data['code_challenge']):
        logger.log_oauth_message(
            "AUTH-SERVER", "AUTH-SERVER",
            "PKCE Verification Failed",
            {
                "error": "invalid_grant",
                "expected_challenge": auth_code_data['code_challenge'][:20] + "...",
                "received_verifier": token_request.code_verifier[:10] + "...",
                "description": "PKCE code verifier does not match challenge"
            }
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_grant",
                "error_description": "PKCE verification failed"
            }
        )

    logger.log_oauth_message(
        "AUTH-SERVER", "AUTH-SERVER",
        "PKCE Verification Successful",
        {
            "code_verifier": token_request.code_verifier[:10] + "...",
            "code_challenge": auth_code_data['code_challenge'][:20] + "...",
            "challenge_method": "S256"
        }
    )

    # Generate access token
    import secrets
    access_token = secrets.token_urlsafe(32)

    # Create token response
    response = TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=3600,
        scope=auth_code_data['scope']
    )

    logger.log_oauth_message(
        "AUTH-SERVER", "CLIENT",
        "Access Token Generated",
        {
            "access_token": access_token[:10] + "...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": auth_code_data['scope'],
            "user_id": auth_code_data['user_id']
        }
    )

    return response