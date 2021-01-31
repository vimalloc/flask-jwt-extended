JWT Locations
=============
JWTs can be passed sent in many different ways to a protected route. These
available ways the tokens can be passed in can be controlled globally via
the `app.config["JWT_TOKEN_LOCATION']` option, or overridden on a per route
basis via the `locations` argument in :func:`~flask_jwt_extended.jwt_required`.
Lets see how working with different locations look like in javascript:

.. literalinclude:: ../examples/jwt_without_cookies.py

Headers
~~~~~~~
There is nothing too crazy when working with JWTs in headers. Simply store the
token when you login, and add the token as a header each time you make a request
to a protected route:

.. code-block :: javascript

  // Login, and save the access token in localStorage
  fetch('/login', {method: 'post'})
    .then(response => response.json())
    .then(data => localStorage.setItem('jwt', data.access_token));

  // Use the access token to make API requests
  fetch('/protected', {
    headers: {
      Authorization: `Bearer ${localStorage.getItem('jwt')}`
    }
  }).then(response => response.json())
    .then(data => console.log(data));

Query Strying
~~~~~~~~~~~~~~
Show how to use query string


JSON Body
~~~~~~~~~
This looks very similar to the Headers approach, except that we send the JWT in
as part of the JSON Body instead of a header. Be aware that HEAD or GET requests
cannot have a JSON body included in the request, so this only works for other
requests like POST/PUT/PATCH/DELETE/etc.

Sending JWTs in a JSON body is probably not very useful most of the time, but
we include the option for it regardless.

.. code-block :: javascript

  // Login, and save the access token in localStorage
  fetch('/login', {method: 'post'})
    .then(response => response.json())
    .then(data => localStorage.setItem('jwt', data.access_token));

  // Use the access token to make API requests
  fetch('/protected', {
    method: 'post',
    body: JSON.stringify({access_token: localStorage.getItem('jwt')}),
    headers: {
      'Content-Type': 'application/json',
    },
  }).then(response => response.json())
    .then(data => console.log(data));

  // This will blow up with the following error, since we are trying to do a GET
  // request with a body: "TypeError: Window.fetch: HEAD or GET Request cannot have a body"
  fetch('/protected', {
    method: 'get',
    body: JSON.stringify({access_token: localStorage.getItem('jwt')}),
    headers: {
      'Content-Type': 'application/json',
    },
  }).then(response => response.json())
    .then(data => console.log(data));


Cookies
~~~~~~~
Show how to use cookies
  - What do we do about setting cookies?
  - CSRF protection
  - Javascript



Overriting Locations On a Per Route Basis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
