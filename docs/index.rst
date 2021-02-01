.. flask-jwt-extended documentation master file, created by
   sphinx-quickstart on Fri Oct  7 10:31:53 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Flask-JWT-Extended's Documentation
==================================

..
    - Installation
    - Basic Usage
    - Automatic User Loading
    - Adding claims to JWTs
    - Optional Endpoints
    - Token Locations
      - Headers
      - Cookies
      - JSON Body
      - Query String
      - locations kwarg for decorator
    - Refresh Tokens
      - Implict refreshing with cookies
        - Prefered for browsers
      - Explict refreshing with refresh tokesn
        - Prefered for non-browsers
    - Fresh Token pattern
      - Here or coupled with refresh tokens?
    - Blocklist and Token Revoking
    - Configuratino Options
    - Modifying Behaviors with Callback Functions
    - Custom Decorators
    - API Documentation

.. toctree::
   :maxdepth: 2

   installation
   basic_usage
   automatic_user_loading
   add_custom_data_claims
   optional_endpoints
   token_locations
   refreshing_tokens
   custom_decorators
   changing_default_behavior
   options
   blocklist_and_token_revoking
   api
