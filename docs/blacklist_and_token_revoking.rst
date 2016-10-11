Blacklist and Token Revoking
============================

This extension supports optional token revoking out of the box. This will
allow you to revoke a specific token so that it can no longer access your endpoints.
In order to revoke a token, we need some storage where we can save a list of all
the tokens we have created, as well as if they have been revoked or not. In order
to make the underlying storage as agnostic as possible, we use `simplekv
<http://pythonhosted.org/simplekv/>`_ to provide assess to a variety of backends.

In production, it is important to use a backend that can have some sort of
persistent storage, so we don't 'forget' that we revoked a token if the flask
process is restarted. We also need something that can be safely used by the
multiple thread and processes running your application. At present we believe
redis is a good fit for this. It has the added benefit of removing expired tokens
from the store automatically, so it wont blow up into something huge.

We also have choose what tokens we want to check against the blacklist. We could
check all tokens (refresh and access), or only the refresh tokens. There are pros
and cons to either way (extra overhead on jwt_required endpoints vs someone being
able to use an access token freely until it expires). In this example, we are going
to only check refresh tokens, and set the access tokes to a small expires time to
help minimize damage that could be done with a stolen access token.

.. literalinclude:: ../examples/blacklist.py

It's worth noting that if your selected backend support the `time to live mixin
<http://pythonhosted.org/simplekv/#simplekv.TimeToLiveMixin>`_ (such as redis),
keys will be automatically deleted from the store at some point after they have
expired. This prevents your store from blowing up with old keys without you having
to do any work to prune it back down.
