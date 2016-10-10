Token Freshness
===============



We have the idea of token freshness built into this extension. In a nutshell,
you can choose to mark some access tokens as fresh and others as non-fresh, and
use the fresh_jwt_required decorator to only allow fresh tokens to access some
views.

This is useful for allowing fresh tokens to do some critical things (maybe
change a password, or complete an online purchase), but to deny those features
to non-fresh tokens without forcing them to re-authenticate. This still allows
your users to access any of the normal jwt_protected endpoints while using a
non-fresh token. This can lead to a more secure site, without creating a
burden on the users experiences by forcing them to always be re-authenticating.

The provided API gives you the power to use the token freshness however you may
want to. A very natural way to do this would be to mark a token as fresh when
they first login, mark any tokens generated with the refresh token to as not
fresh.


.. literalinclude:: ../examples/token_freshness.py

