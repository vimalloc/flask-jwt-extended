JWT Locations
=============
JWTs can be sent in with a request in many different ways. You can control which
ways you want to accept JWTs in your Flask application via the `JWT_TOKEN_LOCATION`
:ref:`configuration option<Configuration Options>`. You can also override that global
configuration on a per route basis via the `locations` argument in
:func:`~flask_jwt_extended.jwt_required`.

.. literalinclude:: ../examples/jwt_locations.py

Lets take a look at how you could utilize all of these locations using some
javascript in a web browser.

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

* They can be configured to send only over HTTPS. This prevents a JWT from
  accidentally being sent, and possibly compromised, over an unsecure connection.
* They are stored in an http-only cookie, which prevents XSS attacks from being
  able to steal the underlying JWT.
* You Flask application can implicitly refresh JWTs that are close to expiring,
  which simplifies the logic of keeping active users logged in. More on this in
  the next section!

Of course, when using cookies you also need to do some additional work to prevent
Cross Site Request Forgery (CSRF) attacks. In this extension we handle this via
something called double submit verification.

The basic idea behind double submit verification is that a JWT coming from a
cookie will only be considered valid if a special double submit token is also
present in the request, and that double submit token must not be something that
is automatically sent by a web browser (ie it cannot be another cookie).

By default, we accomplish this by setting two cookies when someone logging in.
The first cookie contains the JWT, and encoded in that JWT is the double submit
token. This cookie is set as http-only, so that it cannot be access via javascript
(this is what prevents XSS attacks from being able to steal the JWT). The second
cookie we set contains only the same double submit token, but this time in a
cookie that is readable by javascript. Whenever a request is made, it needs to
include an `X-CSRF-TOKEN` header, with the value of the double submit token.
If the value in this header does not match the value stored in the JWT, the
request is kicked out as invalid.

Because the double submit token needs to be present as a header (which wont be
automatically sent on a request), and some malicious javascript running on a
different domain will not be able to read the cookie containing the double submit
token on your website, we have successfully thwarted any CSRF attacks.

This does mean that whenever you are making a request, you need to manually
include the `X-CSRF-TOKEN` header, otherwise your requests will be kicked
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

Note that there are additional CSRF options, such as looking for the double
submit token in a form, changing cookie paths, etc, that can be used to
tailor things to the needs of your application. See
:ref:`Cross Site Request Forgery Options` for details.


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
    const jwt = localStorage.getItem('jwt')
    const response = await fetch(`/protected?jwt=${jwt}`, {method: 'post'});
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
