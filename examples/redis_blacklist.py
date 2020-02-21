# Redis is a very quick in memory store. The benefits of using redis is that
# things will generally speedy, and it can be (mostly) persistent by dumping
# the data to disk (see: https://redis.io/topics/persistence). The drawbacks
# to using redis is you have a higher chance of encountering data loss (in
# this case, 'forgetting' that a token was revoked), when events like
# power outages occur.
#
# When does it make sense to use redis for a blacklist? If you are blacklisting
# every token on logout, and not doing nothing besides that (such as keeping
# track of what tokens are blacklisted, providing options to un-revoke
# blacklisted tokens, or view tokens that are currently active for a user),
# then redis is a great choice. In the worst case, a few tokens might slip
# between the cracks in the case of a power outage or other such event, but
# 99.99% of the time tokens will be properly blacklisted.
#
# Redis also has the benefit of supporting an expires time when storing data.
# Utilizing this, you will not need to manually prune down the stored tokens
# to keep it from blowing up over time. This code includes how to do this.
#
# If you intend to use some other features in your blacklist (tracking
# what tokens are currently active, option to revoke or unrevoke specific
# tokens, etc), data integrity is probably more important to you then
# raw performance. In this case a database solution (such as postgres) is
# probably a better fit for your blacklist. Check out the "database_blacklist"
# example for how that might work.
from datetime import timedelta

import redis
from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jti
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_refresh_token_required
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.secret_key = "ChangeMe!"

# Setup the flask-jwt-extended extension. See:
ACCESS_EXPIRES = timedelta(minutes=15)
REFRESH_EXPIRES = timedelta(days=30)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = REFRESH_EXPIRES
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]
jwt = JWTManager(app)

# Setup our redis connection for storing the blacklisted tokens
revoked_store = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)


# Create our function to check if a token has been blacklisted. In this simple
# case, we will just store the tokens jti (unique identifier) in redis
# whenever we create a new token (with the revoked status being 'false'). This
# function will return the revoked status of a token. If a token doesn't
# exist in this store, we don't know where it came from (as we are adding newly
# created tokens to our store with a revoked status of 'false'). In this case
# we will consider the token to be revoked, for safety purposes.
@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token["jti"]
    entry = revoked_store.get(jti)
    if entry is None:
        return True
    return entry == "true"


@app.route("/auth/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    # Create our JWTs
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    # Store the tokens in redis with a status of not currently revoked. We
    # can use the `get_jti()` method to get the unique identifier string for
    # each token. We can also set an expires time on these tokens in redis,
    # so they will get automatically removed after they expire. We will set
    # everything to be automatically removed shortly after the token expires
    access_jti = get_jti(encoded_token=access_token)
    refresh_jti = get_jti(encoded_token=refresh_token)
    revoked_store.set(access_jti, "false", ACCESS_EXPIRES * 1.2)
    revoked_store.set(refresh_jti, "false", REFRESH_EXPIRES * 1.2)

    ret = {"access_token": access_token, "refresh_token": refresh_token}
    return jsonify(ret), 201


# A blacklisted refresh tokens will not be able to access this endpoint
@app.route("/auth/refresh", methods=["POST"])
@jwt_refresh_token_required
def refresh():
    # Do the same thing that we did in the login endpoint here
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    access_jti = get_jti(encoded_token=access_token)
    revoked_store.set(access_jti, "false", ACCESS_EXPIRES * 1.2)
    ret = {"access_token": access_token}
    return jsonify(ret), 201


# Endpoint for revoking the current users access token
@app.route("/auth/access_revoke", methods=["DELETE"])
@jwt_required
def logout():
    jti = get_jwt()["jti"]
    revoked_store.set(jti, "true", ACCESS_EXPIRES * 1.2)
    return jsonify({"msg": "Access token revoked"}), 200


# Endpoint for revoking the current users refresh token
@app.route("/auth/refresh_revoke", methods=["DELETE"])
@jwt_refresh_token_required
def logout2():
    jti = get_jwt()["jti"]
    revoked_store.set(jti, "true", REFRESH_EXPIRES * 1.2)
    return jsonify({"msg": "Refresh token revoked"}), 200


# A blacklisted access token will not be able to access this any more
@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    return jsonify({"hello": "world"})


if __name__ == "__main__":
    app.run()
