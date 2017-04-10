JWT in Cookies
==============
If the frontend that is consuming this backend is a website, you may be tempted
to store your JWTs in the browser localStorage or sessionStorage. There is nothing
necessarily wrong with this, but if you have any sort of XSS vulnerability on your
site, an attacker will be able to trivially steal your refresh and access tokens.
If you want some additional security on your site, you can save your JWTs in a
httponly cookie instead, which keeps javascript from being able to access the
cookie. See this great blog for a more in depth analysis between these options:
http://www.redotheweb.com/2015/11/09/api-security.html

Here is a basic example of how to store JWTs in cookies:

.. literalinclude:: ../examples/jwt_in_cookie.py

This isn't the full story however. We can now keep our cookie from being stolen via XSS
attacks, but have traded that for a vulnerability to CSRF attacks. To combat
CSRF, we are going to use a technique called double submit verification.

When we create a JWT, we will also create a random string and store it in the JWT. This token is saved
in a cookie with httponly set to True, so it cannot be accessed via javascript.
We will then create a secondary cookie that contains only the random string, but
has httponly set to False, so that it can be accessed via javascript running on
your website. Now in order to access a protected endpoint,
you will need to add a custom header that contains the the random string in it,
and if that header doesn't exist or it doesn't match the string that is stored
in the JWT, the request will be kicked out as unauthorized.

To break this down, if an attacker attempts to perform a CSRF attack they will
send the JWT (via the cookie) to a protected endpoint, but without the random
string in the requests header, they wont be able to access the endpoint. They
cannot access the random string, unless they can run javascript on your website
(likely via an XSS attack), and if they are able to perform an XSS attack, they
will not be able to steal the actual access and refresh JWTs, as javascript is
still not able to access those httponly cookies.

This obviously isn't a golden bullet. If an attacker can perform an XSS attack they can
still access protected endpoints from people who visit your site. However, it is better
then if they were able to steal the access and refresh tokens tokens from
local/session storage, and use them whenever they wanted. If this additional
security is worth the added complexity of using cookies and double submit CSRF
protection is a choice you will have to make.

Here is an example of what this would look like:

.. literalinclude::  ../examples/csrf_protection_with_cookies.py

By default, the CSRF double submit values are sent back as additional cookies
to the caller. If you prefer, you can disable that, and send them back directly
to the caller, like such:

.. code-block:: python

  app.config('JWT_CSRF_IN_COOKIES') = False
  #...
  #...
  #...
  @app.route('/token/auth', methods=['POST'])
  def login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' or password != 'test':
          return jsonify({'login': False}), 401

      # Create the tokens we will be sending back to the user
      access_token = create_access_token(identity=username)
      refresh_token = create_refresh_token(identity=username)

      # Return the double submit values in the resulting JSON
      # instead of in additional cookies
      resp = jsonify({
          'access_csrf': get_csrf_token(access_token),
          'refresh_csrf': get_csrf_token(refresh_token)
      })

      # We still need to call these functions to set the
      # JWTs in the cookies
      set_access_cookies(resp, access_token)
      set_refresh_cookies(resp, refresh_token)
      return resp, 200
