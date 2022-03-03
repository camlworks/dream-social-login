module User_profile = struct
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
end

type provider_error =
  [ `Invalid_request
  | `Unauthorized_client
  | `Access_denied
  | `Unsupported_response_type
  | `Invalid_scope
  | `Server_error
  | `Temporarily_unavailable ]
(** See https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1 *)

let provider_error_of_string = function
  | "invalid_request" -> Some `Invalid_request
  | "unauthorized_client" -> Some `Unauthorized_client
  | "access_denied" -> Some `Access_denied
  | "unsupported_response_type" -> Some `Unsupported_response_type
  | "invalid_scope" -> Some `Invalid_scope
  | "server_error" -> Some `Server_error
  | "temporarily_unavailable" -> Some `Temporarily_unavailable
  | _ -> None

let provider_error_to_string = function
  | `Invalid_request -> "invalid_request"
  | `Unauthorized_client -> "unauthorized_client"
  | `Access_denied -> "access_denied"
  | `Unsupported_response_type -> "unsupported_response_type"
  | `Invalid_scope -> "invalid_scope"
  | `Server_error -> "server_error"
  | `Temporarily_unavailable -> "temporarily_unavailable"

type authenticate_result =
  [ `Ok of User_profile.t
  | `Expired
  | `Provider_error of provider_error * string option
  | `Error of string ]

let log = Dream.sub_log "dream-oauth2"

let authenticate ~access_token ~user_profile req =
  let exception Return of authenticate_result in
  let errorf fmt =
    let kerr message = raise (Return (`Error message)) in
    Printf.ksprintf kerr fmt
  in
  try%lwt
    let () =
      match Dream.query req "error" with
      | None -> ()
      | Some err -> (
        match provider_error_of_string err with
        | Some err ->
          let desc = Dream.query req "error_description" in
          raise (Return (`Provider_error (err, desc)))
        | None -> errorf "provider returned unknown error code: %s" err)
    in
    let%lwt () =
      let state =
        match Dream.query req "state" with
        | Some v -> v
        | None -> errorf "no `state` parameter in callback request"
      in
      match%lwt Dream.verify_csrf_token req state with
      | `Ok -> Lwt.return ()
      | `Expired _ | `Wrong_session -> raise (Return `Expired)
      | `Invalid -> errorf "invalid `state` parameter"
    in
    let code =
      match Dream.query req "code" with
      | Some v -> v
      | None -> errorf "no `code` parameter in callback request"
    in
    let%lwt access_token =
      match%lwt access_token req ~code with
      | Ok access_token -> Lwt.return access_token
      | Error err -> errorf "error getting access_token: %s" err
    in
    let%lwt user_profile =
      match%lwt user_profile req ~access_token with
      | Ok user_profile -> Lwt.return user_profile
      | Error err -> errorf "error getting user_profile: %s" err
    in
    Lwt.return (`Ok user_profile)
  with Return result -> Lwt.return result
