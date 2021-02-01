Custom Decorators
=================

NOTE: THIS DOCUMENTATION HAS NOT YET BEEN UPDATED


You can create your own decorators that extend the functionality of the
decorators provided by this extension. For example, you may want to create
your own decorator that verifies a JWT is present as well as verifying that
this token has sufficient permissions/roles to access an endpoint.

:func:`flask_jwt_extended.verify_jwt_in_request` can be used to build your own decorators.
This is the same function used the :func:`flask_jwt_extended.jwt_required`.

Here is an example of how this might look.

.. literalinclude:: ../examples/custom_decorators.py
