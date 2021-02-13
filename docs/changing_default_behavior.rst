Changing Default Behaviors
==========================

This extension provides sensible default behaviors. For example, if an expired
token attempts to access a protected endpoint, you will get a JSON response back
like ``{"msg": "Token has expired"}`` and a 401 status code. However there may
be various behaviors of this extension that you want to customize to your
application's needs. We can do that with the various loader functions. Here is
an example of how to do that.

.. literalinclude:: ../examples/loaders.py

There are all sorts of callbacks that can be defined to customize the behaviors
of this extension. See the :ref:`Configuring Flask-JWT-Extended` API Documentation
for a full list of callback functions that are available in this extension.
