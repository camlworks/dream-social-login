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

let post ?params ?(headers = []) ?body url_base =
  let body, headers =
    match body with
    | None -> (None, headers)
    | Some (`Form params) ->
      let body = Dream_pure.Formats.to_form_urlencoded params in
      ( Some (Dream_pure.Stream.string body),
        ("Content-Type", "application/x-www-form-urlencoded")
        :: ("Content-Length", Int.to_string (String.length body))
        :: headers )
  in
  Lwt.bind
    (Hyper.run
    @@ Hyper.request (url ?params url_base) ~method_:`POST ?body
         ~headers:(("User-Agent", user_agent) :: headers))
    handle_resp

let get ?params ?(headers = []) url_base =
  Lwt.bind
    (Hyper.run
    @@ Hyper.request (url ?params url_base) ~method_:`GET
         ~headers:(("User-Agent", user_agent) :: headers))
    handle_resp

let parse_json_body ~f resp =
  let%lwt body = Dream_pure.Message.body resp in
  match Yojson.Basic.from_string body with
  | exception Yojson.Json_error _ ->
    log.debug (fun log -> log "error parsing response json body=%s" body);
    Lwt.return_error "error parsing json response body"
  | json ->
    Lwt.return
      (try f json
       with Yojson.Basic.Util.Type_error _ ->
         log.debug (fun log -> log "error parsing response json body=%s" body);
         Error "error parsing json response body")
