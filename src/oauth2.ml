module User_profile = struct
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
end

module type OAUTH2_PROVIDER = sig
  type config
  (** Provider specific configuration.

      This usually contains at least `client_id` and `client_secret` fields but
      may contain more configuration. *)

  val name : string
  (** Unique provider name used to unambigously identify provider. *)

  val authorize_url : state:string -> config -> string
  (** [authorize_url ~state config] produces an URL which starts an
      authentication flow. *)

  val access_token : code:string -> config -> (string, string) result Lwt.t
  (** [access_token ~code config] fetches an access token from the provider. *)

  val user_profile :
    access_token:string -> config -> (User_profile.t, string) result Lwt.t
  (** [user_profile ~access_token config] fetches user profile information from
      the provider API endpoint. *)
end

type t =
  | Oauth2 : {
      config : 'config;
      provider : (module OAUTH2_PROVIDER with type config = 'config);
    }
      -> t

let name (Oauth2 { provider = (module Provider); _ }) = Provider.name
