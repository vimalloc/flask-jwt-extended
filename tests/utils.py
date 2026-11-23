import jwt

from flask_jwt_extended.config import config

JWT_SECRET_KEY = "this_is_at_least_a_32_bit_secret_key_to_stop_test_warnings"


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
    return {"Authorization": f"Bearer {jwt}"}
