from functools import wraps

from flask import Flask, jsonify

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt,
    verify_jwt_in_request,
)

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)


# Here is a custom decorator that verifies the JWT is present in the request,
# as well as insuring that the JWT has a claim indicating that this user is
# an administrator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["is_administrator"]:
                return fn(*args, **kwargs)
            return jsonify(msg="Admins only!"), 403

        return decorator

    return wrapper


@app.route("/login", methods=["POST"])
def login():
    access_token = create_access_token(
        "admin_user", additional_claims={"is_administrator": True}
    )
    return jsonify(access_token=access_token)


@app.route("/protected", methods=["GET"])
@admin_required()
def protected():
    return jsonify(foo="bar")


if __name__ == "__main__":
    app.run()
