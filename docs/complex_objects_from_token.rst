Complex Objects from Tokens
===========================

We can also do the inverse of creating tokens from complex objects like we did
in the last section. In this case, we can take a token and every time a
protected endpoint is accessed automatically use the token to load a complex
object, for example a SQLAlchemy user object. Here's an example of how it
might look:

.. literalinclude:: ../examples/complex_objects_from_tokens.py

If you do not provide a user_loader_callback in your application, and attempt
to access the **current_user** LocalProxy, it will simply be None.

One thing to note with this is that you will now call the **user_loader_callback**
on all of your protected endpoints, which will probably incur the cost of a
database lookup. In most cases this likely isn't a big deal for your application,
but do be aware that it could slow things down if your frontend is doing several
calls to endpoints in rapid succession.
