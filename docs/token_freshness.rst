Token Freshness
===============

The fresh token pattern is built into this extension. This pattern is very
simple, you can choose to mark some access tokens as fresh and others as
non-fresh, and use the :func:`~flask_jwt_extended.fresh_jwt_required` decorator
to only allow fresh tokens to access certain endpoints.

This is useful for allowing fresh tokens to do some critical things (such as
update an email address or complete an online purchase), but to deny those
features to non-fresh tokens. Utilizing Fresh tokens in conjunction with
refresh tokens can lead to a more secure site, without creating a bad user
experience by making users constantly re-authenticate.

Here is an example of how you could utilize refresh tokens with the
fresh token pattern:

.. literalinclude:: ../examples/token_freshness.py
