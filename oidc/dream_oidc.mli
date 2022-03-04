module User_profile = Dream_oauth2.User_profile

type config
(** Configured OIDC client. *)

val configure :
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  string ->
  config
(** Configure an OIDC client. *)

val authorize_url : config -> Dream.request -> string
(** Produce an URL to start signin flow with GitHub. *)

val authenticate :
  config -> Dream.request -> Dream_oauth2.authenticate_result Lwt.t
(** Get the result of authentication. This should be called inside the OAuth2
    callback handler.*)
