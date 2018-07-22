from flask import Flask
from flask_jwt_extended import (
    JWTManager, jwt_required, fresh_jwt_required, jwt_refresh_token_required
)
import pytest


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'secret'
    JWTManager(app)

    @app.route('/jwt_required', methods=["GET", "OPTIONS"])
    @jwt_required
    def jwt_required_endpoint():
        return b'ok'

    @app.route('/fresh_jwt_required', methods=["GET", "OPTIONS"])
    @fresh_jwt_required
    def fresh_jwt_required_endpoint():
        return b'ok'

    @app.route('/jwt_refresh_token_required', methods=["GET", "OPTIONS"])
    @jwt_refresh_token_required
    def jwt_refresh_token_required_endpoint():
        return b'ok'

    return app


def test_access_jwt_required_enpoint(app):
    res = app.test_client().options('/jwt_required')
    assert res.status_code == 200
    assert res.data == b'ok'


def test_access_jwt_refresh_token_required_enpoint(app):
    res = app.test_client().options('/jwt_refresh_token_required')
    assert res.status_code == 200
    assert res.data == b'ok'


def test_access_fresh_jwt_required_enpoint(app):
    res = app.test_client().options('/fresh_jwt_required')
    assert res.status_code == 200
    assert res.data == b'ok'
