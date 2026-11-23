import pytest
from flask import Flask, render_template_string

from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from tests.utils import JWT_SECRET_KEY


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

    @app.route("/context_current_user", methods=["GET"])
    @jwt_required()
    def context_current_user():
        return render_template_string("{{ current_user }}")

    return app


def test_add_context_processor(app):
    jwt_manager = JWTManager(app, add_context_processor=True)

    @jwt_manager.user_lookup_loader
    def user_lookup_callback(_jwt_header, _jwt_data):
        return "test_user"

    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    access_headers = {"Authorization": f"Bearer {access_token}"}
    response = test_client.get("/context_current_user", headers=access_headers)
    assert response.text == "test_user"


def test_no_add_context_processor(app):
    jwt_manager = JWTManager(app)

    @jwt_manager.user_lookup_loader
    def user_lookup_callback(_jwt_header, _jwt_data):
        return "test_user"

    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    access_headers = {"Authorization": f"Bearer {access_token}"}
    response = test_client.get("/context_current_user", headers=access_headers)
    assert response.text == ""
