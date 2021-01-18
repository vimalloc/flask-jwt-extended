import datetime
import uuid
from calendar import timegm

import jwt
from werkzeug.security import safe_str_cmp

from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import JWTDecodeError


def _encode_jwt(
    algorithm,
    claim_overrides,
    csrf,
    expires_delta,
    fresh,
    headers,
    identity,
    identity_claim_key,
    json_encoder,
    secret,
    token_type,
):
    now = datetime.datetime.utcnow()

    if isinstance(fresh, datetime.timedelta):
        fresh = timegm((now + fresh).utctimetuple())

    token_data = {
        "fresh": fresh,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "type": token_type,
        identity_claim_key: identity,
    }

    if csrf:
        token_data["csrf"] = str(uuid.uuid4())

    if expires_delta:
        token_data["exp"] = now + expires_delta

    if claim_overrides:
        token_data.update(claim_overrides)

    return jwt.encode(
        token_data, secret, algorithm, json_encoder=json_encoder, headers=headers
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

    if decoded_token["type"] not in ("access", "refresh"):
        raise JWTDecodeError("Invalid token type: {}".format(decoded_token["type"]))

    if "fresh" not in decoded_token:
        decoded_token["fresh"] = False

    if "jti" not in decoded_token:
        decoded_token["jti"] = None

    if csrf_value:
        if "csrf" not in decoded_token:
            raise JWTDecodeError("Missing claim: csrf")
        if not safe_str_cmp(decoded_token["csrf"], csrf_value):
            raise CSRFError("CSRF double submit tokens do not match")

    return decoded_token
