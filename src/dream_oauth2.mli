module User_profile : sig
  type t = {
    user : string;
    email : string;
  }
  (** Information about an authenticated user. *)
end

val signin_url :
  ?valid_for:float ->
  client_id:string ->
  redirect_uri:string ->
  Dream.request ->
  string
(** Generate an URL which signs user in with an identity provider.

    The optional [valid_for] param specifies (in seconds) the lifetime of the link, the
    default value is [3600.] which is one hour.
  *)

val route :
  client_id:string ->
  client_secret:string ->
  ?redirect_on_signin:string ->
  ?redirect_on_signout:string ->
  ?redirect_on_expired_error:string ->
  unit ->
  Dream.route
(** Create a set of routes for performing authentication with an identity provider.

    The following endpoints are provided:

    - {b /oauth2/callback} receives the callback request from an identity
      provider, validates it, persists authenticated [User_profile.t] information
      and finally redirects to [redirect_on_signin] location (default is ["/"]).

      In case `state` parameter received by the callback is expired then user is
      redirected on [redirect_on_expired_error] location (default is ["/"]).

    - {b /oauth2/signout} drops authentication information and redirects
      to [redirect_on_signout] location (by default it is /).

    Currently this performs authentication against GitHub identity provider.

    Parameters [client_id], [client_secret] and [redirect_uri] should be
    configured according to GitHub OAuth app created.

    See https://github.com/settings/developers page for creating a GitHub OAuth
    app.

 *)

val user_profile : Dream.request -> User_profile.t option
(** [user_profile req] returns [User_profile.t option] information associated
    with the [req] request, if it has any. *)
