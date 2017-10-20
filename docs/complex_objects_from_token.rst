Complex Objects from Tokens
===========================

We can also do the inverse of creating tokens from complex objects like we did
in the last section. In this case, we can take a token and every time a
protected endpoint is accessed, automatically use the token to load a complex
object (such as a SQLAlchemy instance). This is done through the
:meth:`~flask_jwt_extended.JWTManager.user_loader_callback_loader` decorator. The
resulting object can be accessed in your protected endpoints by using the
:func:`~flask_jwt_extended.get_current_user` function, or directly with
the :attr:`~flask_jwt_extended.current_user` LocalProxy.

One thing to note is if you access a database in the
:meth:`~flask_jwt_extended.JWTManager.user_loader_callback_loader`, you will incur
the cost of that database lookup on every call, regardless of if you need
the additional data from the database or not. In most cases this likely isn't
something to be worried about, but do be aware that it could slow your
application if it handles high traffic.

Here's an example of how this feature might look:

.. literalinclude:: ../examples/complex_objects_from_tokens.py

