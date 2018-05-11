Custom Decorators
=================

You can create your own decorators that extend the functionality of the
decorators provided by this extension. For example, you may want to create
your own decorator that verifies a JWT is present as well as verifying that
this token has sufficient permissions/roles to access an endpoint. 

:ref:`Verify Tokens in Request` is a list of functions that can be
used to build your own decorators (these are also what all the default
decorators provided by this extension use internally).

Here is an example of how this might look.

.. literalinclude:: ../examples/custom_decorators.py


