module User_profile : sig
  type t = {
    user : string;
    email : string;
  }
  (** Information about an authenticated user. *)
end

type oauth2_provider_config = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
  scope : string list;
}

module type OAUTH2_PROVIDER = sig
  val authorize_url : state:string -> oauth2_provider_config -> string

  val access_token :
    code:string -> oauth2_provider_config -> (string, string) result Lwt.t

  val user_profile :
    access_token:string -> unit -> (User_profile.t, string) result Lwt.t
end

type oauth2_provider

val oauth2_provider :
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  ?scope:string list ->
  (module OAUTH2_PROVIDER) ->
  oauth2_provider

module Github : OAUTH2_PROVIDER

val signin_url : ?valid_for:float -> oauth2_provider -> Dream.request -> string
(** Generate an URL which signs user in with an identity provider.

    The optional [valid_for] param specifies (in seconds) the lifetime of the link, the
    default value is [3600.] which is one hour.
  *)

val signout_form : ?signout_url:string -> Dream.request -> string
(** Generate an HTML form which performs a logout.

    The form submits a POST request to a CSRF protected [signout_url] (default
    is "/oauth2/signout").

    Application will usually want to implement its own sign out form with custom
    design.
  *)

val route :
  ?redirect_on_signin:string ->
  ?redirect_on_signout:string ->
  ?redirect_on_signin_expired:string ->
  ?redirect_on_signout_expired:string ->
  oauth2_provider ->
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

val signout : Dream.response -> Dream.request -> unit
(** [signout res req] makes a browser receiving the [res] clear the
    authenticated [User_profile.t] info.

    This is a low-level API which can be used to perform a custom sign-out flow.
    Users of this API are responsible for implementing (or not implementing) CSRF
    protection themselves.

  *)
