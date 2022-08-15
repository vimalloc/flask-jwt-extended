import uuid
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from hmac import compare_digest
from json import JSONEncoder
from typing import Any
from typing import Iterable
from typing import List
from typing import Type
from typing import Union

import jwt

from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.typing import ExpiresDelta


def _encode_jwt(
    algorithm: str,
    audience: Union[str, Iterable[str]],
    claim_overrides: dict,
    csrf: bool,
    expires_delta: ExpiresDelta,
    fresh: bool,
    header_overrides: dict,
    identity: Any,
    identity_claim_key: str,
    issuer: str,
    json_encoder: Type[JSONEncoder],
    secret: str,
    token_type: str,
    nbf: bool,
) -> str:
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
        json_encoder=json_encoder,  # type: ignore
        headers=header_overrides,
    )


def _decode_jwt(
    algorithms: List,
    allow_expired: bool,
    audience: Union[str, Iterable[str]],
    csrf_value: str,
    encoded_token: str,
    identity_claim_key: str,
    issuer: str,
    leeway: int,
    secret: str,
    verify_aud: bool,
) -> dict:
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
