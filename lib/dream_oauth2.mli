val route :
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  Dream.route
(** Create a set of routes for performing authentication.

    Currently this performs authentication against GitHub OIDC endpoint.
 *)

val user_profile : Dream.request -> string option
(** [user_profile req] returns user profile information associated with the
    [req] request, if it has any. *)
