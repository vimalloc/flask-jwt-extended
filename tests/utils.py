def get_jwt_manager(app):
    return app.extensions['flask-jwt-extended']


def make_headers(jwt):
    return {'Authorization': 'Bearer {}'.format(jwt)}
