module User_profile : sig
  type t = {
    id : string;
        (** Unique (to provider) user identifier. This corresponds to "sub"
            claim in OIDC *)
    provider : string;
        (** Unique provder identifier. OAuth2 providers have this hardcoded to
            a specific string token ("github", "twitch", ...) while "iss" claim
            is used for OIDC providers. *)
    name : string option;  (** User's name if available. *)
    email : string option;  (** User's email address if available. *)
    email_verified : bool option;
        (** [None] means there's no info about email verification status, [Some
            verified] means the email verification status is [verified], a
            [bool] value. *)
  }
  (** Information about an authenticated user. *)
end

type authenticate_result =
  [ `Ok of User_profile.t
  | `Expired
  | `Provider_error of provider_error * string option
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

and provider_error =
  [ `Invalid_request
  | `Unauthorized_client
  | `Access_denied
  | `Unsupported_response_type
  | `Invalid_scope
  | `Server_error
  | `Temporarily_unavailable ]

val provider_error_to_string : provider_error -> string
val provider_error_of_string : string -> provider_error option

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

module Internal : sig
  module Hyper_helper : sig
    val get :
      ?headers:(string * string) list ->
      Uri.t ->
      (Dream.response, string) Lwt_result.t

    val post :
      ?headers:(string * string) list ->
      ?body:[`Form of (string * string) list | `String of string] ->
      Uri.t ->
      (Dream.response, string) Lwt_result.t

    val url : ?params:(string * string) list -> string -> string

    val parse_json_body :
      f:(Yojson.Basic.t -> ('a, string) result) ->
      Dream.response ->
      ('a, string) Lwt_result.t

    val parse_json :
      f:(Yojson.Basic.t -> ('a, string) result) -> string -> ('a, string) result
  end
end
