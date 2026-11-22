from flask import Flask, jsonify, request

from flask_jwt_extended import JWTManager, create_access_token, get_jwt, jwt_required

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    # You can use the additional_claims argument to either add
    # custom claims or override default claims in the JWT.
    additional_claims = {"aud": "some_audience", "foo": "bar"}
    access_token = create_access_token(username, additional_claims=additional_claims)
    return jsonify(access_token=access_token)


# In a protected view, get the claims you added to the jwt with the
# get_jwt() method
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    claims = get_jwt()
    return jsonify(foo=claims["foo"])


if __name__ == "__main__":
    app.run()
