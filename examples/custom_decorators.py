from functools import wraps

from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    verify_jwt_in_request,
    create_access_token,
    get_jwt_claims,
)

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)


# Here is a custom decorator that verifies the JWT is present in
# the request, as well as insuring that this user has a role of
# `admin` in the access token
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims["roles"] != "admin":
            return jsonify(msg="Admins only!"), 403
        else:
            return fn(*args, **kwargs)

    return wrapper


@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    if identity == "admin":
        return {"roles": "admin"}
    else:
        return {"roles": "peasant"}


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    access_token = create_access_token(username)
    return jsonify(access_token=access_token)


@app.route("/protected", methods=["GET"])
@admin_required
def protected():
    return jsonify(secret_message="go banana!")


if __name__ == "__main__":
    app.run()
