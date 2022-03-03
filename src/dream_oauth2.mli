module User_profile : sig
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
  (** Information about an authenticated user. *)
end

type access_token =
  Dream.request -> code:string -> (string, string) result Lwt.t
(** This represents a type of functions which fetch access_token from an OAuth2
    provider. *)

type user_profile =
  Dream.request -> access_token:string -> (User_profile.t, string) result Lwt.t
(** This represents a type of functions which fetch user profile info from an
    OAuth2 provider. *)

type authenticate_result =
  [ `Ok of User_profile.t
  | `Expired
  | `Error of string ]
(** Result of authentication with OAuth2 provider.

    - [`Ok profile] is a successful case and returns a [User_profile.t] value.
    - [`Expired] signifies that authentication flow is not valid anymore and
      should be restarted.
    - [`Error message] occurs if something goes wrong in the process of
      authentication.
  *)

val authenticate :
  access_token:access_token ->
  user_profile:user_profile ->
  Dream.request ->
  authenticate_result Lwt.t
(** Authenticate request.

    This function should be used in OAuth2 callback, when an OAuth2 provider
    redirects back to your application.

    See [authenticate_result] description on how to handle the result of this
    function. *)

module Github : sig
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
  }

  val authorize_url : config -> Dream.request -> string
  val access_token : config -> access_token
  val user_profile : config -> user_profile
end

module Twitch : sig
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
  }

  val authorize_url : config -> Dream.request -> string
  val access_token : config -> access_token
  val user_profile : config -> user_profile
end

module Stackoverflow : sig
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
    key : string;
  }

  val authorize_url : config -> Dream.request -> string
  val access_token : config -> access_token
  val user_profile : config -> user_profile
end
