"""
Static typing checks for the public decorators.

These are verified by mypy (see the ``mypy`` tox env), which fails if a
decorator starts erasing the type of the function it wraps (e.g. by being
annotated as returning ``Any``). The runtime test makes sure the decorated
objects keep behaving like the originals.
"""

from typing import Dict
from typing import TYPE_CHECKING

from flask import Flask

from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

if TYPE_CHECKING:
    from typing_extensions import assert_type


def test_decorators_preserve_function_types() -> None:
    app = Flask(__name__)
    jwt = JWTManager(app)

    @jwt_required()
    def view(user_id: str) -> Dict[str, str]:
        return {"user_id": user_id}

    @jwt_required(optional=True)
    async def async_view() -> str:
        return "ok"

    @jwt.user_identity_loader
    def identity(user: int) -> str:
        return str(user)

    @jwt.token_in_blocklist_loader
    def in_blocklist(jwt_header: dict, jwt_data: dict) -> bool:
        return False

    if TYPE_CHECKING:
        assert_type(view(""), Dict[str, str])
        assert_type(identity(1), str)
        assert_type(in_blocklist({}, {}), bool)

    assert view.__name__ == "view"
    assert identity(1) == "1"
    assert in_blocklist({}, {}) is False
