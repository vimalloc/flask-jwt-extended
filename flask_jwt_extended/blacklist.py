# Collection of code deals with storing and revoking tokens
import calendar
import datetime
import json

from flask_jwt_extended.exceptions import RevokedTokenError
from functools import wraps

from flask import current_app

from flask_jwt_extended.config import BLACKLIST_ENABLED, BLACKLIST_STORE, \
    BLACKLIST_TOKEN_CHECKS


def _verify_blacklist_enabled(fn):
    """
    Helper decorator that verifies the blacklist is enabled on any function
    that requires it
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        config = current_app.config

        blacklist_enabled = config.get('JWT_BLACKLIST_ENABLED', BLACKLIST_ENABLED)
        if not blacklist_enabled:
            err = 'JWT_BLACKLIST_ENABLED must be True to access this functionality'
            raise RuntimeError(err)

        store = current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)
        if store is None:
            err = 'JWT_BLACKLIST_STORE must be set to access this functionality'
            raise RuntimeError(err)

        check_type = config.get('JWT_BLACKLIST_TOKEN_CHECKS', BLACKLIST_TOKEN_CHECKS)
        if check_type not in ('all', 'refresh'):
            raise RuntimeError('Invalid option for JWT_BLACKLIST_TOKEN_CHECKS')

        return fn(*args, **kwargs)
    return wrapper


def _utc_datetime_to_ts(dt):
    return calendar.timegm(dt.utctimetuple())


def _ts_to_utc_datetime(ts):
    datetime.datetime.utcfromtimestamp(ts)


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
    expires = token['exp']
    now = datetime.datetime.utcnow()
    delta = expires - now

    # If the token is already expired, return that it has a ttl of 0
    if delta.total_seconds() < 0:
        return datetime.timedelta(0)
    return delta


def _get_token_from_store(jti):
    store = current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)
    stored_str = store.get(jti).decode('utf-8')
    stored_data = json.loads(stored_str)
    return stored_data


def _update_token(jti, revoked):
    try:
        stored_data = _get_token_from_store(jti)
        token = stored_data['token']
        store_token(token, revoked)
    except KeyError:
        # Token does not exist in the store. Could have been automatically
        # removed from the store via ttl expiring # (in case of redis or
        # memcached), or could have never been in the store, which probably
        # indicates a bug in the callers code.
        # TODO should this raise an error? Or silently return?
        raise


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
def get_stored_tokens(identity):
    """
    Get a list of stored tokens for this identity. Each token will look like:

    TODO
    """
    # TODO this is *super* inefficient. Come up with a better way
    store = current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)
    data = [json.loads(store.get(jti).decode('utf-8')) for jti in store.iter_keys()]
    return [d for d in data if d['identity'] == identity]


@_verify_blacklist_enabled
def get_all_stored_tokens():
    """
    Get a list of stored tokens for every identity. Each token will look like:

    TODO
    """
    store = current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)
    return [json.loads(store.get(jti).decode('utf-8')) for jti in store.iter_keys()]


@_verify_blacklist_enabled
def check_if_token_revoked(token):
    """
    Checks if the given token has been revoked.
    """
    config = current_app.config

    store = config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)
    check_type = config.get('JWT_BLACKLIST_TOKEN_CHECKS', BLACKLIST_TOKEN_CHECKS)
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
        'last_used': _utc_datetime_to_ts(datetime.datetime.utcnow()),
        'revoked': revoked
    }).encode('utf-8')

    store = current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)

    if _store_supports_ttl(store):
        # Add 15 minutes to ttl to account for possible time drift
        ttl = _get_token_ttl(token) + datetime.timedelta(minutes=15)
        ttl_secs = ttl.total_seconds()
        store.put(token['jti'], data_to_store, ttl_secs=ttl_secs)
    else:
        store.put(token['jti'], data_to_store)
