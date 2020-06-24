from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)


# A demo user object that we will use in this example.
class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles


# An example store of users. In production, this would likely
# be a sqlalchemy instance or something similar.
users_to_roles = {"foo": ["admin"], "bar": ["peasant"], "baz": ["peasant"]}


# This function is called whenever a protected endpoint is accessed,
# and must return an object based on the tokens identity.
# This is called after the token is verified, so you can safely
# use the claims passed in. Note that this needs to
# return None if the user could not be loaded for any reason,
# such as not being found in the underlying data store
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    if identity not in users_to_roles:
        return None

    return UserObject(username=identity, roles=users_to_roles[identity])


# You can override the error returned to the user if the
# user_lookup_callback returns None. If you don't override
# this, # it will return a 401 status code with the JSON:
# {"msg": "Error loading the user <identity>"}.
@jwt.user_lookup_error_loader
def custom_user_lookup_error(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return jsonify(msg="{} not found".format(identity)), 401


# Create a token for any user, so this can be tested out
@app.route("/login", methods=["POST"])
def login():
    username = request.get_json().get("username", None)
    access_token = create_access_token(identity=username)
    ret = {"access_token": access_token}
    return jsonify(ret), 200


# If the user_lookup_callback returns None, this method will
# not be run, even if the access token is valid. You can
# access the loaded user via the ``current_user``` LocalProxy,
# or with the ```get_current_user()``` method
@app.route("/admin-only", methods=["GET"])
@jwt_required
def protected():
    if "admin" not in current_user.roles:
        return jsonify({"msg": "Forbidden"}), 403
    else:
        return jsonify({"msg": "don't forget to drink your ovaltine"})


if __name__ == "__main__":
    app.run()
