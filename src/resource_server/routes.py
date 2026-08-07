"""
Resource Server Routes - OAuth 2.1 Learning Implementation

This module contains the route definitions for the resource server,
including protected endpoints that require OAuth token validation.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from typing import Dict, Any
import sys
import os
from datetime import datetime

# Add the src directory to the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.shared.logging_utils import OAuthLogger
from .middleware import validate_bearer_token, require_scope

# Initialize router and logger
router = APIRouter()
logger = OAuthLogger("RESOURCE-SERVER")


@router.get("/")
async def root():
    """
    Root endpoint providing OAuth 2.1 resource server information.

    Returns comprehensive information about the server capabilities,
    available endpoints, and token requirements.

    Returns:
        JSONResponse: Server information and endpoint documentation
    """
    logger.log_oauth_message(
        "CLIENT", "RESOURCE-SERVER",
        "Service Information Request",
        {
            "endpoint": "/",
            "method": "GET",
            "service": "resource-server"
        }
    )

    return JSONResponse(
        content={
            "service": "OAuth 2.1 Resource Server",
            "description": "Educational OAuth 2.1 resource server with Bearer token validation",
            "version": "1.0.0",
            "oauth_version": "2.1",
            "authentication": {
                "type": "Bearer Token",
                "header": "Authorization: Bearer <access_token>",
                "token_source": "http://localhost:8081/token"
            },
            "endpoints": {
                "root": {
                    "url": "/",
                    "method": "GET",
                    "description": "Service information",
                    "authentication": "none"
                },
                "health": {
                    "url": "/health",
                    "method": "GET",
                    "description": "Health check endpoint",
                    "authentication": "none"
                },
                "status": {
                    "url": "/status",
                    "method": "GET",
                    "description": "Detailed status information",
                    "authentication": "none"
                },
                "protected": {
                    "url": "/protected",
                    "method": "GET",
                    "description": "Protected resource content",
                    "authentication": "Bearer token required"
                },
                "userinfo": {
                    "url": "/userinfo",
                    "method": "GET",
                    "description": "User information endpoint",
                    "authentication": "Bearer token required"
                }
            },
            "security_features": [
                "Bearer token validation",
                "Authorization header parsing",
                "Token format verification",
                "Request/response logging",
                "Security headers"
            ],
            "documentation": {
                "interactive_docs": "/docs",
                "redoc": "/redoc"
            }
        }
    )


@router.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    logger.log_oauth_message(
        "SYSTEM", "RESOURCE-SERVER",
        "Health Check Request",
        {
            "status": "healthy",
            "service": "resource-server"
        }
    )

    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "OAuth Resource Server",
            "version": "1.0.0"
        }
    )


@router.get("/status")
async def status_check():
    """Status endpoint with detailed server information."""
    logger.log_oauth_message(
        "SYSTEM", "RESOURCE-SERVER",
        "Status Check Request",
        {
            "endpoints_available": ["/health", "/status", "/protected", "/userinfo"],
            "authentication_required": ["protected", "userinfo"]
        }
    )

    return JSONResponse(
        status_code=200,
        content={
            "service": "OAuth Resource Server",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "health": "/health",
                "status": "/status",
                "protected": "/protected (requires Bearer token)",
                "userinfo": "/userinfo (requires Bearer token)"
            },
            "authentication": {
                "type": "Bearer Token",
                "header": "Authorization: Bearer <token>"
            }
        }
    )


@router.get("/protected", response_class=PlainTextResponse)
async def protected_resource(
    request: Request,
    token_info: Dict[str, Any] = Depends(validate_bearer_token)
):
    """
    Serve protected resource content that requires valid OAuth token.

    This endpoint demonstrates how to protect resources using OAuth 2.1
    Bearer tokens and provides educational content about the OAuth flow.
    """
    logger.log_oauth_message(
        "CLIENT", "RESOURCE-SERVER",
        "Protected Resource Request",
        {
            "path": "/protected",
            "method": "GET",
            "user_id": token_info.get("user_id"),
            "client_id": token_info.get("client_id"),
            "scope": token_info.get("scope"),
            "token_prefix": token_info.get("token", "")[:10] + "..."
        }
    )

    # Load protected resource content
    try:
        resource_path = os.path.join(
            os.path.dirname(__file__),
            "data",
            "protected-resource.txt"
        )
        # The file contains non-ASCII characters, so the encoding must be
        # explicit -- otherwise Python uses the locale default (e.g. GBK on
        # zh-CN Windows) and raises UnicodeDecodeError.
        with open(resource_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Replace placeholders with actual values
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        token_summary = f"User: {token_info.get('user_id')}, Client: {token_info.get('client_id')}, Scope: {token_info.get('scope')}"

        content = content.replace("{timestamp}", timestamp)
        content = content.replace("{token_info}", token_summary)

    except (FileNotFoundError, OSError, UnicodeDecodeError):
        # Fallback content if file doesn't exist
        content = """🔒 PROTECTED RESOURCE 🔒

Congratulations! You successfully completed the OAuth 2.1 flow!

This is a protected resource that can only be accessed with a valid OAuth access token.

Your token information:
- User ID: {user_id}
- Client ID: {client_id}
- Scope: {scope}
- Access Time: {timestamp}

You have successfully demonstrated OAuth 2.1 with PKCE security!""".format(
            user_id=token_info.get("user_id"),
            client_id=token_info.get("client_id"),
            scope=token_info.get("scope"),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

    logger.log_oauth_message(
        "RESOURCE-SERVER", "CLIENT",
        "Protected Resource Response",
        {
            "resource_size": len(content),
            "content_type": "text/plain",
            "user_id": token_info.get("user_id"),
            "access_granted": True
        }
    )

    return content


@router.get("/userinfo")
async def user_info(
    request: Request,
    token_info: Dict[str, Any] = Depends(validate_bearer_token)
):
    """
    Return user information based on the OAuth token.

    This endpoint provides user profile information for clients
    that have been granted appropriate access via OAuth 2.1.
    """
    logger.log_oauth_message(
        "CLIENT", "RESOURCE-SERVER",
        "User Info Request",
        {
            "path": "/userinfo",
            "method": "GET",
            "user_id": token_info.get("user_id"),
            "client_id": token_info.get("client_id"),
            "requested_scopes": token_info.get("scope")
        }
    )

    # In a real implementation, you would:
    # 1. Look up user details from your user database
    # 2. Filter returned fields based on granted scopes
    # 3. Ensure user consent for information sharing

    # For demo purposes, return mock user information
    user_data = {
        "sub": token_info.get("user_id", "validated-user"),
        "name": "Demo User",
        "email": "demo@example.com",
        "email_verified": True,
        "preferred_username": token_info.get("user_id", "validated-user"),
        "profile": f"https://example.com/users/{token_info.get('user_id', 'validated-user')}",
        "picture": "https://example.com/avatar.jpg",
        "updated_at": "2024-01-01T00:00:00Z",
        "oauth_info": {
            "client_id": token_info.get("client_id"),
            "scope": token_info.get("scope"),
            "token_type": "Bearer",
            "issued_at": datetime.now().isoformat()
        }
    }

    logger.log_oauth_message(
        "RESOURCE-SERVER", "CLIENT",
        "User Info Response",
        {
            "user_id": user_data["sub"],
            "fields_returned": list(user_data.keys()),
            "client_id": token_info.get("client_id"),
            "privacy_compliant": True
        }
    )

    return JSONResponse(
        status_code=200,
        content=user_data
    )