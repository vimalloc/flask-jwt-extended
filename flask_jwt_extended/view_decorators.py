from datetime import datetime
from datetime import timezone
from functools import wraps
from re import split

from flask import _request_ctx_stack
from flask import current_app
from flask import request
from werkzeug.exceptions import BadRequest

from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import FreshTokenRequired
from flask_jwt_extended.exceptions import InvalidHeaderError
from flask_jwt_extended.exceptions import InvalidQueryParamError
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_jwt_extended.exceptions import UserLookupError
from flask_jwt_extended.internal_utils import custom_verification_for_token
from flask_jwt_extended.internal_utils import has_user_lookup
from flask_jwt_extended.internal_utils import user_lookup
from flask_jwt_extended.internal_utils import verify_token_not_blocklisted
from flask_jwt_extended.internal_utils import verify_token_type
from flask_jwt_extended.utils import decode_token
from flask_jwt_extended.utils import get_unverified_jwt_headers


def _verify_token_is_fresh(jwt_header, jwt_data):
    fresh = jwt_data["fresh"]
    if isinstance(fresh, bool):
        if not fresh:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)
    else:
        now = datetime.timestamp(datetime.now(timezone.utc))
        if fresh < now:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)


def verify_jwt_in_request(optional=False, fresh=False, refresh=False, locations=None):
    """
    Verify that a valid JWT is present in the request, unless ``optional=True`` in
    which case no JWT is also considered valid.

    :param optional:
        If ``True``, do not raise an error if no JWT is present in the request.
        Defaults to ``False``.

    :param fresh:
        If ``True``, require a JWT marked as ``fresh`` in order to be verified.
        Defaults to ``False``.

    :param refresh:
        If ``True``, require a refresh JWT to be verified.

    :param locations:
        A location or list of locations to look for the JWT in this request, for
        example ``'headers'`` or ``['headers', 'cookies']``. Defaults to ``None``
        which indicates that JWTs will be looked for in the locations defined by the
        ``JWT_TOKEN_LOCATION`` configuration option.
    """
    if request.method in config.exempt_methods:
        return

    try:
        if refresh:
            jwt_data, jwt_header, jwt_location = _decode_jwt_from_request(
                locations, fresh, refresh=True
            )
        else:
            jwt_data, jwt_header, jwt_location = _decode_jwt_from_request(
                locations, fresh
            )
    except NoAuthorizationError:
        if not optional:
            raise
        _request_ctx_stack.top.jwt = {}
        _request_ctx_stack.top.jwt_header = {}
        _request_ctx_stack.top.jwt_user = {"loaded_user": None}
        _request_ctx_stack.top.jwt_location = None
        return

    # Save these at the very end so that they are only saved in the requet
    # context if the token is valid and all callbacks succeed
    _request_ctx_stack.top.jwt_user = _load_user(jwt_header, jwt_data)
    _request_ctx_stack.top.jwt_header = jwt_header
    _request_ctx_stack.top.jwt = jwt_data
    _request_ctx_stack.top.jwt_location = jwt_location

    return jwt_header, jwt_data


def jwt_required(optional=False, fresh=False, refresh=False, locations=None):
    """
    A decorator to protect a Flask endpoint with JSON Web Tokens.

    Any route decorated with this will require a valid JWT to be present in the
    request (unless optional=True, in which case no JWT is also valid) before the
    endpoint can be called.

    :param optional:
        If ``True``, allow the decorated endpoint to be accessed if no JWT is present in
        the request. Defaults to ``False``.

    :param fresh:
        If ``True``, require a JWT marked with ``fresh`` to be able to access this
        endpoint. Defaults to ``False``.

    :param refresh:
        If ``True``, requires a refresh JWT to access this endpoint. If ``False``,
        requires an access JWT to access this endpoint. Defaults to ``False``.

    :param locations:
        A location or list of locations to look for the JWT in this request, for
        example ``'headers'`` or ``['headers', 'cookies']``. Defaults to ``None``
        which indicates that JWTs will be looked for in the locations defined by the
        ``JWT_TOKEN_LOCATION`` configuration option.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request(optional, fresh, refresh, locations)

            # Compatibility with flask < 2.0
            if hasattr(current_app, "ensure_sync") and callable(
                getattr(current_app, "ensure_sync", None)
            ):
                return current_app.ensure_sync(fn)(*args, **kwargs)

            return fn(*args, **kwargs)  # pragma: no cover

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
    return {"loaded_user": user}


def _decode_jwt_from_headers():
    header_name = config.header_name
    header_type = config.header_type

    # Verify we have the auth header
    auth_header = request.headers.get(header_name, "").strip().strip(",")
    if not auth_header:
        raise NoAuthorizationError(f"Missing {header_name} Header")

    # Make sure the header is in a valid format that we are expecting, ie
    # <HeaderName>: <HeaderType(optional)> <JWT>.
    #
    # Also handle the fact that the header that can be comma delimited, ie
    # <HeaderName>: <field> <value>, <field> <value>, etc...
    if header_type:
        field_values = split(r",\s*", auth_header)
        jwt_headers = [s for s in field_values if s.split()[0] == header_type]
        if len(jwt_headers) != 1:
            msg = (
                f"Missing '{header_type}' type in '{header_name}' header. "
                f"Expected '{header_name}: {header_type} <JWT>'"
            )
            raise NoAuthorizationError(msg)

        parts = jwt_headers[0].split()
        if len(parts) != 2:
            msg = (
                f"Bad {header_name} header. "
                f"Expected '{header_name}: {header_type} <JWT>'"
            )
            raise InvalidHeaderError(msg)

        encoded_token = parts[1]
    else:
        parts = auth_header.split()
        if len(parts) != 1:
            msg = f"Bad {header_name} header. Expected '{header_name}: <JWT>'"
            raise InvalidHeaderError(msg)

        encoded_token = parts[0]

    return encoded_token, None


def _decode_jwt_from_cookies(refresh):
    if refresh:
        cookie_key = config.refresh_cookie_name
        csrf_header_key = config.refresh_csrf_header_name
        csrf_field_key = config.refresh_csrf_field_name
    else:
        cookie_key = config.access_cookie_name
        csrf_header_key = config.access_csrf_header_name
        csrf_field_key = config.access_csrf_field_name

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
    param_name = config.query_string_name
    prefix = config.query_string_value_prefix

    value = request.args.get(param_name)
    if not value:
        raise NoAuthorizationError(f"Missing '{param_name}' query paramater")

    if not value.startswith(prefix):
        raise InvalidQueryParamError(
            f"Invalid value for query parameter '{param_name}'. "
            f"Expected the value to start with '{prefix}'"
        )

    encoded_token = value[len(prefix) :]  # noqa: E203
    return encoded_token, None


def _decode_jwt_from_json(refresh):
    content_type = request.content_type or ""
    if not content_type.startswith("application/json"):
        raise NoAuthorizationError("Invalid content-type. Must be application/json.")

    if refresh:
        token_key = config.refresh_json_key
    else:
        token_key = config.json_key

    try:
        encoded_token = request.json.get(token_key, None)
        if not encoded_token:
            raise BadRequest()
    except BadRequest:
        raise NoAuthorizationError(
            'Missing "{}" key in json data.'.format(token_key)
        ) from None

    return encoded_token, None


def _decode_jwt_from_request(locations, fresh, refresh=False):
    # Figure out what locations to look for the JWT in this request
    if isinstance(locations, str):
        locations = [locations]

    if not locations:
        locations = config.token_location

    # Get the decode functions in the order specified by locations.
    # Each entry in this list is a tuple (<location>, <encoded-token-function>)
    get_encoded_token_functions = []
    for location in locations:
        if location == "cookies":
            get_encoded_token_functions.append(
                (location, lambda: _decode_jwt_from_cookies(refresh))
            )
        elif location == "query_string":
            get_encoded_token_functions.append(
                (location, _decode_jwt_from_query_string)
            )
        elif location == "headers":
            get_encoded_token_functions.append((location, _decode_jwt_from_headers))
        elif location == "json":
            get_encoded_token_functions.append(
                (location, lambda: _decode_jwt_from_json(refresh))
            )
        else:
            raise RuntimeError(f"'{location}' is not a valid location")

    # Try to find the token from one of these locations. It only needs to exist
    # in one place to be valid (not every location).
    errors = []
    decoded_token = None
    jwt_header = None
    jwt_location = None
    for location, get_encoded_token_function in get_encoded_token_functions:
        try:
            encoded_token, csrf_token = get_encoded_token_function()
            decoded_token = decode_token(encoded_token, csrf_token)
            jwt_location = location
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

    # Additional verifications provided by this extension
    verify_token_type(decoded_token, refresh)
    if fresh:
        _verify_token_is_fresh(jwt_header, decoded_token)
    verify_token_not_blocklisted(jwt_header, decoded_token)
    custom_verification_for_token(jwt_header, decoded_token)

    return decoded_token, jwt_header, jwt_location
