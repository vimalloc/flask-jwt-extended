import pytest
from flask import Flask, jsonify

from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from tests.utils import JWT_SECRET_KEY

RSA_PRIVATE = """
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3oPEDz3Fgd9gx
halGnCyjdjOiszQb7qTPwEOZulPpYqOggbiayh1jRVUyT+JUPZflAzig3QDin9IA
eQPW2iYVfo+FYE+g8PcF2a6cQXAbbibW85t80tVfWElL0H9xQKb3XVYTb0MvnBX4
NWNHVDBQGY1uB4qN4d6wzBiD1i9DigwBPNWLZT9hSerAQifdrS8RqnGIXZfLIRyY
WDlTVl11nzAWie6zfSuAzWueoCs5R1oTXFp6tSd4NN8kkutVrPuoF7OtjK4vn9p8
9vmRdyt8atDSSzXhWDQOAIE71/xBaO4hi8OfTZgJoT1WvZHwLOQ0pjKwqzsLZN32
fgGRtw63AgMBAAECggEANSE52tJgiXrjcKCts6JoP/tpQT/8acCIqxuD86y3rqU9
lqkx0od8LUbYObBnWdxgYICoF9MZ+HgpeL2K4NVJg5qUyBBvua8+qdCr9sXwO9+J
GVRuvpT565ZNzsPKu+fq51N4HjNpCxNsP96ilPbE68gY5acE7bxWhGzpAuwrzKxc
sx3mtyJVbT4oCh0Bw0s7wkFTZsrdFEtFPMQQaxBSlqzPQ3WkSbPr8I+qvKgDMwnY
mqnkji+57HUks2o+kqkUyIxkqC84BI4dbg6RHP7SUtR6XqlOr2MYpIJnZwbbW3b2
TOFZjvpRQb5SbCH8FgmjIyDHR7jhFe+TEeptt6YaAQKBgQDpU6wP6QYWcA4hjqOo
LcETUE+MAK/a0kAM/RE7bFdIAj3MzKe9SR6vM1tUQ3HjBpoaIqmEYGrpuhRr6lSq
WxEzU7HCMv+9WspybCVy0cFNE42/1dCsl3+2LQUi1dwnISovgNz8RLaT+bz3Nho+
Y55BFUKPzWg5j1fSLZ/FcgTqNwKBgQDJePVvdXs078f1sD3O/HUuH4Vtq1gJnQry
SFap4sYyVCXgrelTJikppRIHoxNIWITAph00jWuISn4TQdFbglJ0TnEo2ck7aYdD
xgZTQ163scGkzamir/fCR1R5diCFrv89lxoabsL4jwUUD5FQQSxPMShBN47QkvdZ
sMM9CnK/gQKBgDYj8y3x7Taxo6XHulPg4gdAQGUFF8kXtkMNSb1XI12TH5Hw/w8d
81/F8/A2giuisYlU966+zLAVPH3Z7vFkljYpunqMaOkgMw+f5oShBVCENAUKcRRL
RxgXlDSEGUR/HpHNPfnPW+o0LdPTGv3VEbiaXUqO6BtLFp6vdX5UOa27AoGATUaQ
1RR5kl9aEflsa6TXiT5b3im3VdCfbzihzP2HSayO7rOl59eeODPxS26YKcqR+JZ+
YzbPBPKVkutO0suUtrmTm7iU/63FTRB6Qpt3i/upK34az6Sw4hqb4w6VANGTYts/
Dt5m+BFbQEuMT/z/csyHBSS7KXMFXqh26kXEp4ECgYB6D7Hw61EdhSJoBHKyEpyT
yglDZg06Eovc1UQp+OVPMvTG9bqK469DLJI+SWsqYzVF4lmXTsf/rXJy5EfeFUv9
gIaHGpbs6pZvM+OeSGtUmhcz6wT02eiCND1/oL40tJ8atK+3m7EwHu2DIZZE4gKe
a8tRwsMBR16BTx11W9EbEg==
-----END PRIVATE KEY-----
"""


RSA_PUBLIC = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt6DxA89xYHfYMYWpRpws
o3YzorM0G+6kz8BDmbpT6WKjoIG4msodY0VVMk/iVD2X5QM4oN0A4p/SAHkD1tom
FX6PhWBPoPD3BdmunEFwG24m1vObfNLVX1hJS9B/cUCm911WE29DL5wV+DVjR1Qw
UBmNbgeKjeHesMwYg9YvQ4oMATzVi2U/YUnqwEIn3a0vEapxiF2XyyEcmFg5U1Zd
dZ8wFonus30rgM1rnqArOUdaE1xaerUneDTfJJLrVaz7qBezrYyuL5/afPb5kXcr
fGrQ0ks14Vg0DgCBO9f8QWjuIYvDn02YCaE9Vr2R8CzkNKYysKs7C2Td9n4BkbcO
twIDAQAB
-----END PUBLIC KEY-----
"""


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    app.config["JWT_PUBLIC_KEY"] = RSA_PUBLIC
    app.config["JWT_PRIVATE_KEY"] = RSA_PRIVATE
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def protected():
        return jsonify(foo="bar")

    return app


def test_asymmetric_cropto(app):
    test_client = app.test_client()

    with app.test_request_context():
        hs256_token = create_access_token("username")
        app.config["JWT_ALGORITHM"] = "RS256"
        rs256_token = create_access_token("username")

    # Ensure the symmetric token does not work now
    access_headers = {"Authorization": f"Bearer {hs256_token}"}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 422
    assert response.get_json() == {"msg": "The specified alg value is not allowed"}

    # Ensure the asymmetric token does work
    access_headers = {"Authorization": f"Bearer {rs256_token}"}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}
