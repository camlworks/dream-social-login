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
(** Create a set of routes for performing authentication.

    Currently this performs authentication against GitHub OIDC endpoint.
 *)

val user_profile : Dream.request -> User_profile.t option
(** [user_profile req] returns [User_profile.t] information associated with the
    [req] request, if it has any. *)
