from blacklist_helpers import add_token_to_database
from blacklist_helpers import get_user_tokens
from blacklist_helpers import is_token_revoked
from blacklist_helpers import revoke_token
from blacklist_helpers import unrevoke_token
from exceptions import TokenNotFound
from extensions import db
from extensions import jwt
from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_refresh_token_required
from flask_jwt_extended import jwt_required


# We will use an in memory sqlite database for this example. In production,
# I would recommend postgres.
def create_app():
    app = Flask(__name__)

    app.secret_key = "ChangeMe!"
    app.config["JWT_BLACKLIST_ENABLED"] = True
    app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    jwt.init_app(app)

    # In a real application, these would likely be blueprints
    register_endpoints(app)

    return app


def register_endpoints(app):
    # Make sure the sqlalchemy database is created
    @app.before_first_request
    def setup_sqlalchemy():
        db.create_all()

    # Define our callback function to check if a token has been revoked or not
    @jwt.token_in_blacklist_loader
    def check_if_token_revoked(decoded_token):
        return is_token_revoked(decoded_token)

    @app.route("/auth/login", methods=["POST"])
    def login():
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        if username != "test" or password != "test":
            return jsonify({"msg": "Bad username or password"}), 401

        # Create our JWTs
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)

        # Store the tokens in our store with a status of not currently revoked.
        add_token_to_database(access_token, app.config["JWT_IDENTITY_CLAIM"])
        add_token_to_database(refresh_token, app.config["JWT_IDENTITY_CLAIM"])

        ret = {"access_token": access_token, "refresh_token": refresh_token}
        return jsonify(ret), 201

    # A revoked refresh tokens will not be able to access this endpoint
    @app.route("/auth/refresh", methods=["POST"])
    @jwt_refresh_token_required
    def refresh():
        # Do the same thing that we did in the login endpoint here
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        add_token_to_database(access_token, app.config["JWT_IDENTITY_CLAIM"])
        return jsonify({"access_token": access_token}), 201

    # Provide a way for a user to look at their tokens
    @app.route("/auth/token", methods=["GET"])
    @jwt_required
    def get_tokens():
        user_identity = get_jwt_identity()
        all_tokens = get_user_tokens(user_identity)
        ret = [token.to_dict() for token in all_tokens]
        return jsonify(ret), 200

    # Provide a way for a user to revoke/unrevoke their tokens
    @app.route("/auth/token/<token_id>", methods=["PUT"])
    @jwt_required
    def modify_token(token_id):
        # Get and verify the desired revoked status from the body
        json_data = request.get_json(silent=True)
        if not json_data:
            return jsonify({"msg": "Missing 'revoke' in body"}), 400
        revoke = json_data.get("revoke", None)
        if revoke is None:
            return jsonify({"msg": "Missing 'revoke' in body"}), 400
        if not isinstance(revoke, bool):
            return jsonify({"msg": "'revoke' must be a boolean"}), 400

        # Revoke or unrevoke the token based on what was passed to this function
        user_identity = get_jwt_identity()
        try:
            if revoke:
                revoke_token(token_id, user_identity)
                return jsonify({"msg": "Token revoked"}), 200
            else:
                unrevoke_token(token_id, user_identity)
                return jsonify({"msg": "Token unrevoked"}), 200
        except TokenNotFound:
            return jsonify({"msg": "The specified token was not found"}), 404


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
