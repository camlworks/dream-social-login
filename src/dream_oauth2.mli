module User_profile : sig
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
  (** Information about an authenticated user. *)
end

type authenticate_result =
  [ `Ok of User_profile.t
  | `Expired
  | `Provider_error of string * string option
  | `Error of string ]
(** Result of authentication with OAuth2 provider.

    - [`Ok profile] is a successful case and returns a [User_profile.t] value.
    - [`Expired] signifies that authentication flow is not valid anymore and
      should be restarted.
    - [`Provider_error (message, desc)] is the error returned from the provider
      with the optional description.
    - [`Error message] occurs if something else goes wrong in the process of
      authentication.
  *)

module Github : sig
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
  }
  (** Configuration required for Github OAuth2 client.

      See https://docs.github.com/en/developers/apps/building-oauth-apps *)

  val authorize_url : config -> Dream.request -> string
  (** Produce an URL to start signin flow with GitHub. *)

  val authenticate : config -> Dream.request -> authenticate_result Lwt.t
  (** Get the result of authentication. This should be called inside the OAuth2
      callback handler.*)
end

module Twitch : sig
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
  }
  (** Configuration required for Twitch OAuth2 client.

      See https://dev.twitch.tv/docs/authentication *)

  val authorize_url : config -> Dream.request -> string
  (** Produce an URL to start signin flow with Twitch. *)

  val authenticate : config -> Dream.request -> authenticate_result Lwt.t
  (** Get the result of authentication. This should be called inside the OAuth2
      callback handler.*)
end

module Stackoverflow : sig
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
    key : string;
  }
  (** Configuration required for Stackoverflow OAuth2 client.

      See https://api.stackexchange.com/docs/authentication *)

  val authorize_url : config -> Dream.request -> string
  (** Produce an URL to start signin flow with Stackoverflow. *)

  val authenticate : config -> Dream.request -> authenticate_result Lwt.t
  (** Get the result of authentication. This should be called inside the OAuth2
      callback handler.*)
end
