# Google Login Proxy

**WIP: insecure as things stand. Do not use (yet).**

Provides a simple proxy with Google login for authorisation.

Users are invited to login with their Google account when first
hitting the proxy, and are authed from then on provided their email is
from the approved domain.

## How it works

Users are authenticated with Google using Oauth2. Once this is done,
the user's email address is stored as a session cookie, in JWT token
format. HMAC is used to encrypt the token.

The cookie is set to expire in 30 days if the user has not closed
their browser session before then.

## TODOs

* fix 'state' variable
* preserve initial path after login (currently returns you to root)
* add some tests around security behaviour!
* make things configurable / cli options/env
