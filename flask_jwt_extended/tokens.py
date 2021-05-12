import uuid
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from hmac import compare_digest

import jwt

from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import JWTDecodeError


def _encode_jwt(
    algorithm,
    audience,
    claim_overrides,
    csrf,
    expires_delta,
    fresh,
    header_overrides,
    identity,
    identity_claim_key,
    issuer,
    json_encoder,
    secret,
    token_type,
    nbf,
):
    now = datetime.now(timezone.utc)

    if isinstance(fresh, timedelta):
        fresh = datetime.timestamp(now + fresh)

    token_data = {
        "fresh": fresh,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": token_type,
        identity_claim_key: identity,
    }

    if nbf:
        token_data["nbf"] = now

    if csrf:
        token_data["csrf"] = str(uuid.uuid4())

    if audience:
        token_data["aud"] = audience

    if issuer:
        token_data["iss"] = issuer

    if expires_delta:
        token_data["exp"] = now + expires_delta

    if claim_overrides:
        token_data.update(claim_overrides)

    return jwt.encode(
        token_data,
        secret,
        algorithm,
        json_encoder=json_encoder,
        headers=header_overrides,
    )


def _decode_jwt(
    algorithms,
    allow_expired,
    audience,
    csrf_value,
    encoded_token,
    identity_claim_key,
    issuer,
    leeway,
    secret,
    verify_aud,
):
    options = {"verify_aud": verify_aud}
    if allow_expired:
        options["verify_exp"] = False

    # This call verifies the ext, iat, and nbf claims
    # This optionally verifies the exp and aud claims if enabled
    decoded_token = jwt.decode(
        encoded_token,
        secret,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
        leeway=leeway,
        options=options,
    )

    # Make sure that any custom claims we expect in the token are present
    if identity_claim_key not in decoded_token:
        raise JWTDecodeError("Missing claim: {}".format(identity_claim_key))

    if "type" not in decoded_token:
        decoded_token["type"] = "access"

    if "fresh" not in decoded_token:
        decoded_token["fresh"] = False

    if "jti" not in decoded_token:
        decoded_token["jti"] = None

    if csrf_value:
        if "csrf" not in decoded_token:
            raise JWTDecodeError("Missing claim: csrf")
        if not compare_digest(decoded_token["csrf"], csrf_value):
            raise CSRFError("CSRF double submit tokens do not match")

    return decoded_token
