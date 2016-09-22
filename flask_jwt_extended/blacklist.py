# Collection of code deals with storing and revoking tokens
import calendar
import datetime
import json
from functools import wraps

from flask_jwt_extended.config import get_blacklist_checks, \
    get_blacklist_store, get_blacklist_enabled
from flask_jwt_extended.exceptions import RevokedTokenError


def _verify_blacklist_enabled(fn):
    """
    Helper decorator that verifies the blacklist is enabled on any function
    that requires it
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        blacklist_enabled = get_blacklist_enabled()
        if not blacklist_enabled:
            err = 'JWT_BLACKLIST_ENABLED must be True to access this functionality'
            raise RuntimeError(err)

        store = get_blacklist_store()
        if store is None:
            err = 'JWT_BLACKLIST_STORE must be set to access this functionality'
            raise RuntimeError(err)

        check_type = get_blacklist_checks()
        if check_type not in ('all', 'refresh'):
            raise RuntimeError('Invalid option for JWT_BLACKLIST_TOKEN_CHECKS')

        return fn(*args, **kwargs)
    return wrapper


def _ts_to_utc_datetime(ts):
    return datetime.datetime.utcfromtimestamp(ts)


def _store_supports_ttl(store):
    """
    Checks if this store supports a TTL on its keys, for automatic removal
    after the token has expired. For more info on this, see:
    http://pythonhosted.org/simplekv/#simplekv.TimeToLiveMixin
    """
    return getattr(store, 'ttl_support', False)


def _get_token_ttl(token):
    """
    Returns a datetime.timdelta() of how long this token has left to live before
    it is expired
    """
    expires = _ts_to_utc_datetime(token['exp'])
    now = datetime.datetime.utcnow()
    delta = expires - now

    # If the token is already expired, return that it has a ttl of 0
    if delta.total_seconds() < 0:
        return datetime.timedelta(0)
    return delta


def _get_token_from_store(jti):
    store = get_blacklist_store()
    stored_str = store.get(jti).decode('utf-8')
    stored_data = json.loads(stored_str)
    return stored_data


def _update_token(jti, revoked):
    # Raises a KeyError if the token is not found in the store
    stored_data = _get_token_from_store(jti)
    token = stored_data['token']
    store_token(token, revoked)


@_verify_blacklist_enabled
def revoke_token(jti):
    """
    Revoke a token

    :param jti: The jti of the token to revoke
    """
    _update_token(jti, revoked=True)


@_verify_blacklist_enabled
def unrevoke_token(jti):
    """
    Revoke a token

    :param jti: The jti of the token to revoke
    """
    _update_token(jti, revoked=False)


@_verify_blacklist_enabled
def get_stored_token(jti):
    return _get_token_from_store(jti)


@_verify_blacklist_enabled
def get_stored_tokens(identity):
    """
    Get a list of stored tokens for this identity. Each token will look like:

    TODO
    """
    # TODO this is *super* inefficient. Come up with a better way
    store = get_blacklist_store()
    data = [json.loads(store.get(jti).decode('utf-8')) for jti in store.iter_keys()]
    return [d for d in data if d['token']['identity'] == identity]


@_verify_blacklist_enabled
def get_all_stored_tokens():
    """
    Get a list of stored tokens for every identity. Each token will look like:

    TODO
    """
    store = get_blacklist_store()
    return [json.loads(store.get(jti).decode('utf-8')) for jti in store.iter_keys()]


@_verify_blacklist_enabled
def check_if_token_revoked(token):
    """
    Checks if the given token has been revoked.
    """
    store = get_blacklist_store()
    check_type = get_blacklist_checks()
    token_type = token['type']
    jti = token['jti']

    # Only check access tokens if BLACKLIST_TOKEN_CHECKS is set to 'all`
    if token_type == 'access' and check_type == 'all':
        stored_data = json.loads(store.get(jti).decode('utf-8'))
        if stored_data['revoked']:
            raise RevokedTokenError('Token has been revoked')

    # Always check refresh tokens
    if token_type == 'refresh':
        stored_data = json.loads(store.get(jti).decode('utf-8'))
        if stored_data['revoked']:
            raise RevokedTokenError('Token has been revoked')


@_verify_blacklist_enabled
def store_token(token, revoked):
    """
    Stores this token in our key-value store, with the given revoked status
    """
    data_to_store = json.dumps({
        'token': token,
        'revoked': revoked
    }).encode('utf-8')

    store = get_blacklist_store()

    if _store_supports_ttl(store):  # pragma: no cover
        # Add 15 minutes to ttl to account for possible time drift
        ttl = _get_token_ttl(token) + datetime.timedelta(minutes=15)
        ttl_secs = ttl.total_seconds()
        store.put(token['jti'], data_to_store, ttl_secs=ttl_secs)
    else:
        store.put(token['jti'], data_to_store)
