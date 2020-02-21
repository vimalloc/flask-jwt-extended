from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import get_raw_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)


# This is an example of a complex object that we could build
# a JWT from. In practice, this will likely be something
# like a SQLAlchemy instance.
class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles


# Create a function that will be called whenever create_access_token
# is used. It will take whatever object is passed into the
# create_access_token method, and lets us define what custom claims
# should be added to the access token.
@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {"roles": user.roles}


# Create a function that will be called whenever create_access_token
# is used. It will take whatever object is passed into the
# create_access_token method, and lets us define what the identity
# of the access token should be.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    # Create an example UserObject
    user = UserObject(username="test", roles=["foo", "bar"])

    # We can now pass this complex object directly to the
    # create_access_token method. This will allow us to access
    # the properties of this object in the user_claims_loader
    # function, and get the identity of this object from the
    # user_identity_loader function.
    access_token = create_access_token(identity=user)
    ret = {"access_token": access_token}
    return jsonify(ret), 200


@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    ret = {
        "current_identity": get_jwt_identity(),  # test
        "current_roles": get_raw_jwt()["roles"],  # ['foo', 'bar']
    }
    return jsonify(ret), 200


if __name__ == "__main__":
    app.run()
