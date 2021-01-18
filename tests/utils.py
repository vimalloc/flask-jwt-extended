import jwt

from flask_jwt_extended.config import config


def encode_token(app, token_data, headers=None):
    with app.test_request_context():
        return jwt.encode(
            token_data,
            config.decode_key,
            algorithm=config.algorithm,
            json_encoder=config.json_encoder,
            headers=headers,
        )


def get_jwt_manager(app):
    return app.extensions["flask-jwt-extended"]


def make_headers(jwt):
    return {"Authorization": "Bearer {}".format(jwt)}
