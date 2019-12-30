from flask import Flask, jsonify, request

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)

# IMPORTANT: Body is meaningless in GET requests, so using json
# as the only lookup method means that the GET method will become
# unauthorized in any protected route, as there's no body to look for.

app.config["JWT_TOKEN_LOCATION"] = ["json"]
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!

jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


# The default attribute name where the JWT is looked for is `access_token`,
# and can be changed with the JWT_JSON_KEY option.
# Notice how the route is unreachable with GET requests.
@app.route("/protected", methods=["GET", "POST"])
@jwt_required
def protected():
    return jsonify(foo="bar")


if __name__ == "__main__":
    app.run()
