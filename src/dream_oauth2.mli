module User_profile : sig
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
  (** Information about an authenticated user. *)
end

type oauth2
(** Values of this type represend configured OAuth2 providers. *)

val github :
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  oauth2
(** Configure GitHub OAuth2 provider.

    See https://docs.github.com/en/developers/apps/building-oauth-apps *)

val stackoverflow :
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  key:string ->
  unit ->
  oauth2
(** Configure StackOverflow OAuth2 provider.

    See https://api.stackexchange.com/docs/authentication *)

val twitch :
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  oauth2
(** Configure Twitch OAuth2 provider.

    See https://dev.twitch.tv/docs/authentication *)

val signin_url : ?valid_for:float -> oauth2 -> Dream.request -> string
(** Generate an URL which signs user in with an OAuth2 provider.

    The optional [valid_for] param specifies (in seconds) the lifetime of the
    link, the default value is [3600.] which is one hour. *)

val signout_form : ?signout_url:string -> Dream.request -> string
(** Generate an HTML form which performs a logout.

    The form submits a POST request to a CSRF protected [signout_url] (default
    is "/oauth2/signout").

    Application will usually want to implement its own sign out form with custom
    design. *)

val route :
  ?redirect_on_signin:string ->
  ?redirect_on_signout:string ->
  ?redirect_on_signin_expired:string ->
  ?redirect_on_signout_expired:string ->
  oauth2 list ->
  Dream.route
(** Create a set of routes for performing authentication with OAuth2
    providers.

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
    app. *)

val user_profile : Dream.request -> User_profile.t option
(** [user_profile req] returns [User_profile.t option] information associated
    with the [req] request, if it has any. *)

val signout : Dream.response -> Dream.request -> unit
(** [signout res req] makes a browser receiving the [res] clear the
    authenticated [User_profile.t] info.

    This is a low-level API which can be used to perform a custom sign-out flow.
    Users of this API are responsible for implementing (or not implementing) CSRF
    protection themselves. *)
