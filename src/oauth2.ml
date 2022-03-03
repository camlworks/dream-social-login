module User_profile = struct
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
end

type authenticate_result =
  [ `Ok of User_profile.t
  | `Expired
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
      | Some err -> errorf "provider returned: %s" err
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
