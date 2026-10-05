"""
Static typing checks for the public decorators.

These are verified by mypy (see the ``mypy`` tox env), which fails if a
decorator starts erasing the type of the function it wraps (e.g. by being
annotated as returning ``Any``). The runtime tests make sure the decorated
objects keep behaving like the originals.
"""
from typing import Any
from typing import Callable
from typing import Coroutine
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

from flask import Flask
from flask import Response

from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

if TYPE_CHECKING:
    from typing_extensions import assert_type


def test_jwt_required_preserves_function_types() -> None:
    @jwt_required()
    def view(user_id: str) -> Dict[str, str]:
        return {"user_id": user_id}

    @jwt_required(optional=True)
    async def async_view() -> str:
        return "ok"

    if TYPE_CHECKING:
        assert_type(view(""), Dict[str, str])
        assert_type(async_view, Callable[[], Coroutine[Any, Any, str]])

    assert view.__name__ == "view"
    assert async_view.__name__ == "async_view"


def test_loaders_preserve_function_types() -> None:
    app = Flask(__name__)
    jwt = JWTManager(app)

    @jwt.additional_claims_loader
    def additional_claims(identity: int) -> Dict[str, int]:
        return {"identity": identity}

    @jwt.additional_headers_loader
    def additional_headers(identity: int) -> Dict[str, str]:
        return {"kid": str(identity)}

    @jwt.decode_key_loader
    def decode_key(jwt_header: dict, jwt_data: dict) -> str:
        return "decode-key"

    @jwt.encode_key_loader
    def encode_key(identity: int) -> str:
        return "encode-key"

    @jwt.expired_token_loader
    def expired_token(jwt_header: dict, jwt_data: dict) -> Response:
        return Response("expired", status=401)

    @jwt.invalid_token_loader
    def invalid_token(reason: str) -> Response:
        return Response(reason, status=422)

    @jwt.needs_fresh_token_loader
    def needs_fresh_token(jwt_header: dict, jwt_data: dict) -> Response:
        return Response("needs fresh", status=401)

    @jwt.revoked_token_loader
    def revoked_token(jwt_header: dict, jwt_data: dict) -> Response:
        return Response("revoked", status=401)

    @jwt.token_in_blocklist_loader
    def in_blocklist(jwt_header: dict, jwt_data: dict) -> bool:
        return False

    @jwt.token_verification_failed_loader
    def verification_failed(jwt_header: dict, jwt_data: dict) -> Response:
        return Response("verification failed", status=400)

    @jwt.token_verification_loader
    def verify_token(jwt_header: dict, jwt_data: dict) -> bool:
        return True

    @jwt.unauthorized_loader
    def unauthorized(reason: str) -> Response:
        return Response(reason, status=401)

    @jwt.user_identity_loader
    def identity(user: int) -> str:
        return str(user)

    @jwt.user_lookup_loader
    def user_lookup(jwt_header: dict, jwt_data: dict) -> Optional[int]:
        return 1

    @jwt.user_lookup_error_loader
    def user_lookup_error(jwt_header: dict, jwt_data: dict) -> Response:
        return Response("user not found", status=401)

    if TYPE_CHECKING:
        assert_type(additional_claims(1), Dict[str, int])
        assert_type(additional_headers(1), Dict[str, str])
        assert_type(decode_key({}, {}), str)
        assert_type(encode_key(1), str)
        assert_type(expired_token({}, {}), Response)
        assert_type(invalid_token(""), Response)
        assert_type(needs_fresh_token({}, {}), Response)
        assert_type(revoked_token({}, {}), Response)
        assert_type(in_blocklist({}, {}), bool)
        assert_type(verification_failed({}, {}), Response)
        assert_type(verify_token({}, {}), bool)
        assert_type(unauthorized(""), Response)
        assert_type(identity(1), str)
        assert_type(user_lookup({}, {}), Optional[int])
        assert_type(user_lookup_error({}, {}), Response)

    assert additional_claims(1) == {"identity": 1}
    assert additional_headers(1) == {"kid": "1"}
    assert decode_key({}, {}) == "decode-key"
    assert encode_key(1) == "encode-key"
    assert expired_token({}, {}).status_code == 401
    assert invalid_token("bad").status_code == 422
    assert needs_fresh_token({}, {}).status_code == 401
    assert revoked_token({}, {}).status_code == 401
    assert in_blocklist({}, {}) is False
    assert verification_failed({}, {}).status_code == 400
    assert verify_token({}, {}) is True
    assert unauthorized("missing").status_code == 401
    assert identity(1) == "1"
    assert user_lookup({}, {}) == 1
    assert user_lookup_error({}, {}).status_code == 401
