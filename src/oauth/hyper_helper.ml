(* XXX: should be added by Hyper? *)
let user_agent = "hyper/1.0.0"
let log = Dream.sub_log "dream-oauth2-http"

let url ?(params = []) base =
  match params with
  | [] -> base
  | params -> Printf.sprintf "%s?%s" base (Hyper.to_form_urlencoded params)

let handle_resp resp =
  match Dream_pure.Message.status resp with
  | #Dream_pure.Status.successful -> (
    match%lwt Dream_encoding.with_decoded_body resp with
    | Ok resp -> Lwt.return_ok resp
    | Error err ->
      log.debug (fun log -> log "error decoding response body: %s" err);
      Lwt.return_error "error decoding response body")
  | status ->
    let status = Dream_pure.Status.status_to_string status in
    let%lwt body =
      match%lwt Dream_encoding.with_decoded_body resp with
      | Ok resp -> Dream_pure.Message.body resp
      | Error _ -> Lwt.return "<error>"
    in
    log.debug (fun log -> log "request failed status=%s body=%s" status body);
    Lwt.return_error ("response status code: " ^ status)

let post ?(headers = []) ?body uri =
  let uri =
    match Uri.scheme uri with
    | Some "https" -> Uri.with_uri ~port:(Some 443) uri
    | _ -> uri
  in
  let body, headers =
    match body with
    | None -> (None, headers)
    | Some (`String body) ->
      ( Some body,
        ("Content-Length", Int.to_string (String.length body)) :: headers )
    | Some (`Form params) ->
      let body = Dream_pure.Formats.to_form_urlencoded params in
      ( Some body,
        ("Content-Type", "application/x-www-form-urlencoded")
        :: ("Content-Length", Int.to_string (String.length body))
        :: headers )
  in
  Lwt.bind
    (Hyper.run
    @@ Hyper.request (Uri.to_string uri) ~method_:`POST ?body
         ~headers:
           (("Host", Uri.host uri |> Option.get)
           :: ("User-Agent", user_agent)
           :: headers))
    handle_resp

let get ?(headers = []) uri =
  let uri =
    match Uri.scheme uri with
    | Some "https" -> Uri.with_uri ~port:(Some 443) uri
    | _ -> uri
  in
  Lwt.bind
    (Hyper.run
    @@ Hyper.request (Uri.to_string uri) ~method_:`GET
         ~headers:
           (("Host", Uri.host uri |> Option.get)
           :: ("User-Agent", user_agent)
           :: headers))
    handle_resp

let parse_json ~f data =
  match Yojson.Basic.from_string data with
  | exception Yojson.Json_error _ ->
    log.debug (fun log -> log "error parsing response json body=%s" data);
    Error "error parsing json response body"
  | json -> (
    try f json
    with Yojson.Basic.Util.Type_error _ | Yojson.Safe.Util.Type_error _ ->
      log.debug (fun log -> log "error parsing response json body=%s" data);
      Error "error parsing json response body")

let parse_json_body ~f resp =
  let%lwt body = Dream_pure.Message.body resp in
  Lwt.return (parse_json ~f body)
