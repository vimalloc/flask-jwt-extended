from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,  current_user
)

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# A user object that we will load our tokens
class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles

# An example store of users. In production, this would likely
# be a sqlalchemy instance or something similiar
users_to_roles = {
    'foo': ['admin'],
    'bar': ['peasant'],
    'baz': ['peasant']
}


# This function is called whenever a protected endpoint is accessed.
# This should return a complex object based on the token identity.
# This is called after the token is verified, so you can use
# get_jwt_claims() in here if desired. Note that this needs to
# return None if the user could not be loaded for any reason,
# such as not being found in the underlying data store
@jwt.user_loader_callback_loader
def user_loader_callback(identity):
    if identity not in users_to_roles:
        return None

    return UserObject(
        username=identity,
        roles=users_to_roles[identity]
    )


# You can override the error returned to the user if the
# user_loader_callback returns None. By default, if you don't
# override this, it will return a 401 status code with the json:
# {'msg': "Error loading the user <identity>"}. You can use
# get_jwt_claims() here too if desired
@jwt.user_loader_error_loader
def custom_user_loader_error(identity):
    return jsonify({"msg": "User not found"}), 404


# Create a token for any user, so this can be tested out
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    access_token = create_access_token(identity=username)
    ret = {'access_token': access_token}
    return jsonify(ret), 200


# If the user_loader_callback returns None, this method will
# not get hit, even if the access token is valid. You can
# access the loaded user via the ``current_user``` LocalProxy,
# or with the ```get_current_user()``` method
@app.route('/admin-only', methods=['GET'])
@jwt_required
def protected():
    if 'admin' not in current_user.roles:
        return jsonify({"msg": "Forbidden"}), 403
    return jsonify({"secret_msg": "don't forget to drink your ovaltine"})

if __name__ == '__main__':
    app.run()
