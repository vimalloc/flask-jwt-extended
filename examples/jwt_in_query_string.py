from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

# IMPORTANT NOTE:
# In most cases this is not recommended! It can lead some some
# security issues, such as:
#    - The browser saving GET request urls in it's history that
#      has a JWT in the query string
#    - The backend server logging JWTs that are in the url
#
# If possible, you should use headers instead!

app = Flask(__name__)
app.config["JWT_TOKEN_LOCATION"] = ["query_string"]
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


# The default query paramater where the JWT is looked for is `jwt`,
# and can be changed with the JWT_QUERY_STRING_NAME option. Making
# a request to this endpoint would look like:
# /protected?jwt=<ACCESS_TOKEN>
@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    return jsonify(foo="bar")


if __name__ == "__main__":
    app.run()
