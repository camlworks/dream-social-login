## Running the example app

Create a [new OAuth app][gh-oauth-app] and initialize the following environment
variables:

    export OAUTH2_CLIENT_ID="..."
    export OAUTH2_CLIENT_SECRET="..."
    export OAUTH2_REDIRECT_URI="http://localhost:8080"

Initialize opam environment:

    export OPAMSWITCH="$PWD"
    make init
    eval $(opam env)

Start the app:

    make start

[gh-oauth-app]: https://github.com/settings/developers
