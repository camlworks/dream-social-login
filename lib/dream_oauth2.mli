module User_profile : sig
  type t = { user : string; email : string }
  (** Information about an authenticated user. *)
end

val route :
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  ?redirect_on_signin:string ->
  ?redirect_on_signout:string ->
  unit ->
  Dream.route
(** Create a set of routes for performing authentication with an OIDC provider.

    The following endpoints are provided:

    - {b /oauth2/signin} initiates the authentication flow. The user is
      redirected to the OIDC provider.

    - {b /oauth2/callback} receives the callback request from OIDC provider,
      validates it, persists authenticated [User_profile.t] information and
      finally redirects to [redirect_on_signin] location (by default it is /).

    - {b /oauth2/signout} drops authentication information and redirects
      to [redirect_on_signout] location (by default it is /).

    Currently this performs authentication against GitHub OIDC endpoint.

    Parameters [client_id], [client_secret] and [redirect_uri] should be
    configured according to GitHub OAuth app created.

    See https://github.com/settings/developers page for creating a GitHub OAuth
    app.

 *)

val user_profile : Dream.request -> User_profile.t option
(** [user_profile req] returns [User_profile.t option] information associated
    with the [req] request, if it has any. *)
