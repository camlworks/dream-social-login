## Running the example app

Create a [new OAuth app][gh-oauth-app] and initialize the following environment
variables:

    export OAUTH2_CLIENT_ID="..."
    export OAUTH2_CLIENT_SECRET="..."
    export OAUTH2_REDIRECT_URI="http://localhost:8080/oauth2/callback"

Depending on how you run the example app you might need to customize
`OAUTH2_REDIRECT_URI` value - it should be the one GitHub could reach the app.

Initialize opam environment:

    export OPAMSWITCH="$PWD"
    make init
    eval $(opam env)

Start the app:

    make start

[gh-oauth-app]: https://github.com/settings/developers
