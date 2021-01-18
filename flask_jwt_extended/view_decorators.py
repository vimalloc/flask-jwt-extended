from calendar import timegm
from datetime import datetime
from functools import wraps
from re import split

from flask import _request_ctx_stack
from flask import request
from werkzeug.exceptions import BadRequest

from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import FreshTokenRequired
from flask_jwt_extended.exceptions import InvalidHeaderError
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_jwt_extended.exceptions import UserLookupError
from flask_jwt_extended.utils import _custom_verification_for_token
from flask_jwt_extended.utils import decode_token
from flask_jwt_extended.utils import get_unverified_jwt_headers
from flask_jwt_extended.utils import has_user_lookup
from flask_jwt_extended.utils import user_lookup
from flask_jwt_extended.utils import verify_token_not_blocklisted
from flask_jwt_extended.utils import verify_token_type


def _verify_token_is_fresh(jwt_header, jwt_data):
    fresh = jwt_data["fresh"]
    if isinstance(fresh, bool):
        if not fresh:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)
    else:
        now = timegm(datetime.utcnow().utctimetuple())
        if fresh < now:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)


def verify_jwt_in_request(optional=False, fresh=False, refresh=False, locations=None):
    """
    Ensure that the requester has a valid access token. This does not check the
    freshness of the access token. Raises an appropiate exception there is
    no token or if the token is invalid.
    """
    if request.method in config.exempt_methods:
        return

    try:
        if refresh:
            jwt_data, jwt_header = _decode_jwt_from_request("refresh", locations)
        else:
            jwt_data, jwt_header = _decode_jwt_from_request("access", locations)
    except (NoAuthorizationError, InvalidHeaderError):
        if not optional:
            raise
        _request_ctx_stack.top.jwt = {}
        _request_ctx_stack.top.jwt_header = {}
        return

    if fresh:
        _verify_token_is_fresh(jwt_header, jwt_data)
    if not refresh or config.user_claims_in_refresh_token:
        _custom_verification_for_token(jwt_header, jwt_data)

    # Save these at the very end so that they are only saved in the requet
    # context if the token is valid and all callbacks succeed
    _request_ctx_stack.top.jwt_user = _load_user(jwt_header, jwt_data)
    _request_ctx_stack.top.jwt_header = jwt_header
    _request_ctx_stack.top.jwt = jwt_data

    return jwt_header, jwt_data


def jwt_required(optional=False, fresh=False, refresh=False, locations=None):
    """
    A decorator to protect a Flask endpoint.

    If you decorate an endpoint with this, it will ensure that the requester
    has a valid access token before allowing the endpoint to be called. This
    does not check the freshness of the access token.

    See also: :func:`~flask_jwt_extended.fresh_jwt_required`
    """

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request(optional, fresh, refresh, locations)
            return fn(*args, **kwargs)

        return decorator

    return wrapper


def _load_user(jwt_header, jwt_data):
    if not has_user_lookup():
        return None

    identity = jwt_data[config.identity_claim_key]
    user = user_lookup(jwt_header, jwt_data)
    if user is None:
        error_msg = "user_lookup returned None for {}".format(identity)
        raise UserLookupError(error_msg, jwt_header, jwt_data)
    return user


def _decode_jwt_from_headers():
    header_name = config.header_name
    header_type = config.header_type

    # Verify we have the auth header
    auth_header = request.headers.get(header_name, None)
    if not auth_header:
        raise NoAuthorizationError("Missing {} Header".format(header_name))

    # Make sure the header is in a valid format that we are expecting, ie
    # <HeaderName>: <HeaderType(optional)> <JWT>
    jwt_header = None

    # Check if header is comma delimited, ie
    # <HeaderName>: <field> <value>, <field> <value>, etc...
    if header_type:
        field_values = split(r",\s*", auth_header)
        jwt_header = [s for s in field_values if s.split()[0] == header_type]
        if len(jwt_header) < 1 or len(jwt_header[0].split()) != 2:
            msg = "Bad {} header. Expected value '{} <JWT>'".format(
                header_name, header_type
            )
            raise InvalidHeaderError(msg)
        jwt_header = jwt_header[0]
    else:
        jwt_header = auth_header

    parts = jwt_header.split()
    if not header_type:
        if len(parts) != 1:
            msg = "Bad {} header. Expected value '<JWT>'".format(header_name)
            raise InvalidHeaderError(msg)
        encoded_token = parts[0]
    else:
        encoded_token = parts[1]

    return encoded_token, None


def _decode_jwt_from_cookies(token_type):
    if token_type == "access":
        cookie_key = config.access_cookie_name
        csrf_header_key = config.access_csrf_header_name
        csrf_field_key = config.access_csrf_field_name
    else:
        cookie_key = config.refresh_cookie_name
        csrf_header_key = config.refresh_csrf_header_name
        csrf_field_key = config.refresh_csrf_field_name

    encoded_token = request.cookies.get(cookie_key)
    if not encoded_token:
        raise NoAuthorizationError('Missing cookie "{}"'.format(cookie_key))

    if config.csrf_protect and request.method in config.csrf_request_methods:
        csrf_value = request.headers.get(csrf_header_key, None)
        if not csrf_value and config.csrf_check_form:
            csrf_value = request.form.get(csrf_field_key, None)
        if not csrf_value:
            raise CSRFError("Missing CSRF token")
    else:
        csrf_value = None

    return encoded_token, csrf_value


def _decode_jwt_from_query_string():
    query_param = config.query_string_name
    encoded_token = request.args.get(query_param)
    if not encoded_token:
        raise NoAuthorizationError('Missing "{}" query paramater'.format(query_param))

    return encoded_token, None


def _decode_jwt_from_json(token_type):
    content_type = request.content_type or ""
    if not content_type.startswith("application/json"):
        raise NoAuthorizationError("Invalid content-type. Must be application/json.")

    if token_type == "access":
        token_key = config.json_key
    else:
        token_key = config.refresh_json_key

    try:
        encoded_token = request.json.get(token_key, None)
        if not encoded_token:
            raise BadRequest()
    except BadRequest:
        raise NoAuthorizationError('Missing "{}" key in json data.'.format(token_key))

    return encoded_token, None


def _decode_jwt_from_request(token_type, locations):
    # All the places we can get a JWT from in this request
    get_encoded_token_functions = []

    # Get locations in the order specified by the decorator or JWT_TOKEN_LOCATION
    # configuration.
    if not locations:
        locations = config.token_location

    # Add the functions in the order specified by locations.
    for location in locations:
        if location == "cookies":
            get_encoded_token_functions.append(
                lambda: _decode_jwt_from_cookies(token_type)
            )
        if location == "query_string":
            get_encoded_token_functions.append(_decode_jwt_from_query_string)
        if location == "headers":
            get_encoded_token_functions.append(_decode_jwt_from_headers)
        if location == "json":
            get_encoded_token_functions.append(
                lambda: _decode_jwt_from_json(token_type)
            )

    # Try to find the token from one of these locations. It only needs to exist
    # in one place to be valid (not every location).
    errors = []
    decoded_token = None
    jwt_header = None
    for get_encoded_token_function in get_encoded_token_functions:
        try:
            encoded_token, csrf_token = get_encoded_token_function()
            decoded_token = decode_token(encoded_token, csrf_token)
            jwt_header = get_unverified_jwt_headers(encoded_token)
            break
        except NoAuthorizationError as e:
            errors.append(str(e))

    # Do some work to make a helpful and human readable error message if no
    # token was found in any of the expected locations.
    if not decoded_token:
        if len(locations) > 1:
            err_msg = "Missing JWT in {start_locs} or {end_locs} ({details})".format(
                start_locs=", ".join(locations[:-1]),
                end_locs=locations[-1],
                details="; ".join(errors),
            )
            raise NoAuthorizationError(err_msg)
        else:
            raise NoAuthorizationError(errors[0])

    verify_token_type(decoded_token, expected_type=token_type)
    verify_token_not_blocklisted(jwt_header, decoded_token, token_type)
    return decoded_token, jwt_header
