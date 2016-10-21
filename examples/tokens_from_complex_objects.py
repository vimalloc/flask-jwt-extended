from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, \
    create_access_token, get_jwt_identity

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!

# Setup the Flask-JWT-Extended extension
jwt = JWTManager(app)


# This is a simple example of a complex object that we could build
# a JWT from. In practice, this will normally be something that
# requires a lookup from disk (such as SQLAlchemy)
class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles


# This method will get whatever object is passed into the
# create_access_token method.
@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {'roles': user.roles}


# This method will also get whatever object is passed into the
# create_access_token method, and let us define what the identity
# should be for this object
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Create an example UserObject
    user = UserObject(username='test', roles=['foo', 'bar'])

    # We can now pass this complex object directly to the
    # create_access_token method. This will allow us to access
    # the properties of this object in the user_claims_loader
    # function, and get the identity of this object from the
    # user_identity_loader function.
    # function how to get the identity from this object
    access_token = create_access_token(identity=user)
    ret = {'access_token': access_token}
    return jsonify(ret), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    current_user = get_jwt_identity()
    return jsonify({'hello_from': current_user}), 200

if __name__ == '__main__':
    app.run()
