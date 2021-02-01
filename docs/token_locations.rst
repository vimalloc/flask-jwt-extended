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
Working JWTs via headers is a pretty simple process. All you need to do is store
the token when you login, and add the token as a header each time you make a
request to a protected route. Logging out is as simple as deleting the token.

.. code-block :: javascript

  async function login() {
    const response = await fetch('/login_without_cookies', {method: 'post'});
    const result = await response.json();
    localStorage.setItem('jwt', result.access_token);
  }

  function logout() {
    localStorage.removeItem('jwt');
  }

  async function makeRequestWithJWT() {
    const options = {
      method: 'post',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('jwt')}`,
      }
    };
    const response = await fetch('/protected', options);
    const result = await response.json();
    return result;
  }


Cookies
~~~~~~~
Cookies are a fantastic way of handling JWTs if you are using a web browser.
They offer some nice benefits compared to the headers approach:

* They can be set to send only if you are on an HTTPS connection. This prevents a
  JWT from accidentally being leaked by being sent over an unsecure connection.
* They are stored in an http-only cookie, which prevents XSS attacks from being
  able to steal the underlying JWT.
* You flask application can implicitly refresh JWTs that are close to expiring,
  which simplifies the logic of keeping active users logged in. More on this in
  the next section!

Of course, when using cookies you also need to do some additional work to prevent
Cross Site Request Forgery (CSRF) attacks. In this extension we do this by utilizing
the double submit verification method. The basic idea behind this is that we are
going to save two cookies when logging in. The first cookie contains the access
token, and encoded in the access token is double submit token. This cookie is
set as http-only, so javascript cannot access the cookie to decode the double
submit token. The second cookie we save contains only the same double submit
token, but this time in a cookie that is readable by javascript. Whenever a
request is made, it needs to include an `X-CSRF-TOKEN` header, with the value
of the double submit token. If the value in this header does not match the value
stored in the access token, the request is kicked out as invalid. This prevents
any CSRF attacks, because although they can implictitly send in the JWT as part
of the request, they have no way to also include the double submit token.

This does mean that whenever you are making a request, you need to manually
include the double submit token header, otherwise your requests will be kicked
out as invalid too. Lets look at how to do that:

.. code-block :: javascript

  async function login() {
    await fetch('/login_with_cookies', {method: 'post'});
  }

  async function logout() {
    await fetch('/logout_with_cookies', {method: 'post'});
  }

  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }

  async function makeRequestWithJWT() {
    const options = {
      method: 'post',
      headers: {
        'X-CSRF-TOKEN': getCookie('csrf_access_token'),
      },
    };
    const response = await fetch('/protected', options);
    const result = await response.json();
    return result;
  }


Query String
~~~~~~~~~~~~~
You can also send in the JWT as part of the query string. However, It is very
important to note that in most cases we recommend *NOT* doing this. It can lead
to some non-obvious security issues, such as saving the JWT in a browsers history
or the JWT being logged in your backend server, which could both potentially
lead to a compromised token. However, this feature might provide some limited
usefulness, such as sending password reset links, and therefore we support it
in this extension.

.. code-block :: javascript

  async function login() {
    const response = await fetch('/login_without_cookies', {method: 'post'});
    const result = await response.json();
    localStorage.setItem('jwt', result.access_token);
  }

  function logout() {
    localStorage.removeItem('jwt');
  }

  async function makeRequestWithJWT() {
    const response = await fetch('/protected', {method: 'post'});
    const result = await response.json();
    return result;
  }


JSON Body
~~~~~~~~~
This looks very similar to the Headers approach, except that we send the JWT in
as part of the JSON Body instead of a header. Be aware that HEAD or GET requests
cannot have a JSON body as part of the request, so this only works for actions
like POST/PUT/PATCH/DELETE/etc.

Sending JWTs in a JSON body is probably not very useful most of the time, but
we include the option for it regardless.

.. code-block :: javascript

  async function login() {
    const response = await fetch('/login_without_cookies', {method: 'post'});
    const result = await response.json();
    localStorage.setItem('jwt', result.access_token);
  }

  function logout() {
    localStorage.removeItem('jwt');
  }

  // Note that if we change the method to `get` this will blow up with a
  // "TypeError: Window.fetch: HEAD or GET Request cannot have a body"
  async function makeRequestWithJWT() {
    const options = {
      method: 'post',
      body: JSON.stringify({access_token: localStorage.getItem('jwt')}),
      headers: {
        'Content-Type': 'application/json',
      },
    };
    const response = await fetch('/protected', options);
    const result = await response.json();
    return result;
  }


Overwriting Locations On a Per Route Basis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
