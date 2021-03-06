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

See:

* https://tools.ietf.org/html/rfc6749 (oauth2)
* https://tools.ietf.org/html/rfc7519 (JWT)

## Building

If you want to work on the code itself, download the sources:

    $ go get github.com/guardian/google-login-proxy/...

(Requires a working go installation.)

Then run or build as you like. E.g.

    $ go run main.go
    $ GOARCH=amd64 GOOS=linux go build . // build for linux

## TODOs

- [x] add some tests around security behaviour!
- [ ] fix 'state' variable
- [ ] redirect to kibana home after login
- [ ] make things configurable / cli options/env
