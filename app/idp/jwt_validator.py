"""JWT Validator — validates enterprise JWTs and extracts identity claims.

Security model:
    - JWTs are NEVER decoded without signature verification.
    - All standard claims (iss, aud, exp, nbf) are validated by PyJWT.
    - No custom cryptographic logic is implemented here.
    - PyJWT's jwt.decode() with algorithms=["RS256", "ES256"] handles
      all cryptographic verification using the ``cryptography`` backend.

Claim extraction:
    - The groups claim key is configurable (IDP_GROUPS_CLAIM, default "groups").
    - Enterprise IdPs differ: Keycloak uses "groups", Azure Entra may use
      "roles" or a custom claim, Cognito uses "cognito:groups".
    - If the claim is missing, we return an empty list — the caller (auth
      layer) decides whether to treat this as a 403.
    - IdP groups and IdP roles are distinct concepts.  This module reads
      only the configured groups claim.  IdP roles are not used in Phase 1.
"""

from __future__ import annotations

from typing import Any

import jwt
from jwt import PyJWK

from app.exceptions import AuthenticationError, MaskingAPIError
from app.idp.jwks_client import JWKSFetchError, JWKSKeyNotFoundError, get_signing_key
from app.idp.oidc_discovery import OIDCDiscoveryError, fetch_oidc_metadata


# ── Public API ────────────────────────────────────────────────────────────────

async def validate_jwt(
    token: str,
    issuer: str,
    audience: str,
    *,
    jwks_uri_override: str | None = None,
) -> dict[str, Any]:
    """Validate *token* and return its verified claims.

    Parameters
    ----------
    token:
        The raw JWT string from the ``Authorization: Bearer <token>`` header.
    issuer:
        Expected ``iss`` claim value.  Also used as the base URL for OIDC
        discovery unless *jwks_uri_override* is provided.
    audience:
        Expected ``aud`` claim value.
    jwks_uri_override:
        If set, OIDC discovery is skipped and this URI is used directly.
        Intended for air-gapped environments or development mocks.

    Returns
    -------
    dict
        The verified claims payload.

    Raises
    ------
    AuthenticationError (HTTP 401)
        For any JWT validation failure: invalid signature, expired token,
        wrong issuer, wrong audience, malformed token, unknown kid.
    JWKSFetchError (HTTP 503)
        When the JWKS endpoint cannot be reached.
    """
    # ── Step 1: Decode header (unverified) to get kid and alg ────────────────
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.DecodeError as exc:
        raise AuthenticationError(f"Malformed JWT: {exc}") from exc

    kid: str | None = unverified_header.get("kid")
    alg: str = unverified_header.get("alg", "")

    if alg not in ("RS256", "ES256", "RS384", "RS512", "ES384", "ES512"):
        raise AuthenticationError(
            f"JWT algorithm '{alg}' is not accepted. "
            "Only RS256, RS384, RS512, ES256, ES384, ES512 are permitted."
        )

    # ── Step 2: Resolve JWKS URI ──────────────────────────────────────────────
    if jwks_uri_override:
        jwks_uri = jwks_uri_override
    else:
        try:
            metadata = await fetch_oidc_metadata(issuer)
        except OIDCDiscoveryError as exc:
            # Re-raise as a 503; the IdP is unreachable, not the token's fault.
            raise exc
        jwks_uri = metadata.jwks_uri

    # ── Step 3: Fetch the signing key ─────────────────────────────────────────
    # JWKSFetchError (503) and JWKSKeyNotFoundError (401) propagate as-is.
    raw_jwk = await get_signing_key(jwks_uri, kid)

    # ── Step 4: Build a PyJWK and verify ─────────────────────────────────────
    try:
        pyjwk = PyJWK.from_dict(raw_jwk)
    except Exception as exc:
        raise AuthenticationError(f"Failed to load JWK: {exc}") from exc

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            pyjwk.key,
            algorithms=[alg],
            issuer=issuer,
            audience=audience,
            options={
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_signature": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("JWT has expired.") from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthenticationError(f"JWT issuer is not trusted: {exc}") from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthenticationError(f"JWT audience mismatch: {exc}") from exc
    except jwt.ImmatureSignatureError as exc:
        raise AuthenticationError("JWT is not yet valid (nbf).") from exc
    except jwt.InvalidSignatureError as exc:
        raise AuthenticationError("JWT signature verification failed.") from exc
    except jwt.DecodeError as exc:
        raise AuthenticationError(f"JWT decode error: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError(f"Invalid JWT: {exc}") from exc

    return claims


def extract_groups(claims: dict[str, Any], groups_claim_key: str) -> list[str]:
    """Extract the groups list from *claims* using *groups_claim_key*.

    Returns an empty list if the claim is absent or not a list.
    The caller is responsible for deciding what to do with an empty result
    (typically: HTTP 403 because no group means no profile mapping).

    Notes
    -----
    - IdP groups and IdP roles are different concepts.  This function reads
      only the configured groups claim, not any roles claim.
    - Different IdPs use different claim names:
        Keycloak:   ``groups``
        Azure AD:   ``groups`` (object IDs) or ``roles``
        Cognito:    ``cognito:groups``
        Okta:       ``groups`` (requires a groups claim scope/policy)
      Use IDP_GROUPS_CLAIM to configure the correct name for your IdP.
    """
    raw = claims.get(groups_claim_key)
    if not isinstance(raw, list):
        return []
    # Filter to string values only; ignore any non-string entries defensively.
    return [g for g in raw if isinstance(g, str)]
