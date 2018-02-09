from flask import Flask, Blueprint
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import pytest

@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'secret'
    JWTManager(app)

    protected_bp = Blueprint('protected', __name__)

    # This protects the entire blueprint,
    # Also the OPTIONS method
    @protected_bp.before_request
    @jwt_required
    def protect():
        pass

    @protected_bp.route('/protected', methods=["GET"])
    @jwt_required
    def protected():
        return 'ok'

    app.register_blueprint(protected_bp)
    return app


def test_access_protected_enpoint(app):
    client = app.test_client()
    assert client.get('/protected').status_code == 401 # ok

def test_access_protected_enpoint_options(app):
    client = app.test_client()
    assert client.options('/protected').status_code == 200 # test fails
