(* TODO should be added by Hyper? *)
let user_agent = "hyper/1.0.0"
let log = Dream.sub_log "dream-oauth2-http"
(* TODO Do we really need a separate sub-log? *)

let url ?(params = []) base =
  match params with
  | [] -> base
  | params -> Printf.sprintf "%s?%s" base (Hyper.to_form_urlencoded params)
    (* TODO Consider using uri library here. *)

let handle response =
  match Hyper.status response with
  | #Hyper.successful ->
    begin match%lwt Dream_encoding.with_decoded_body response with
    | Ok response ->
      Lwt.return_ok response
    | Error error ->
      log.debug (fun log -> log "error decoding response body: %s" error);
      Lwt.return_error "error decoding response body"
    end
  | status ->
    let status = Hyper.status_to_string status in
    let%lwt body =
      match%lwt Dream_encoding.with_decoded_body response with
      | Ok response -> Hyper.body response
      | Error _ -> Lwt.return "<error>"
    in
    (* TODO Should the body be logged here? *)
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
    | None ->
      (None, headers)
    | Some (`String body) ->
      let headers =
        ("Content-Length", Int.to_string (String.length body))::headers in
      (Some body, headers)
    | Some (`Form params) ->
      let body = Hyper.to_form_urlencoded params in
      let headers =
        ("Content-Type", "application/x-www-form-urlencoded")::
        ("Content-Length", Int.to_string (String.length body))::
        headers
      in
      (Some body, headers)
  in
  let headers =
    ("Host", Uri.host uri |> Option.get)::
    ("User-Agent", user_agent)::
    headers
  in
  let%lwt response =
    Hyper.run
    @@ Hyper.request ~method_:`POST ?body ~headers (Uri.to_string uri)
  in
  handle response

let get ?(headers = []) uri =
  let uri =
    match Uri.scheme uri with
    | Some "https" -> Uri.with_uri ~port:(Some 443) uri
    | _ -> uri
  in
  let headers =
    ("Host", Uri.host uri |> Option.get)::
    ("User-Agent", user_agent)::
    headers
  in
  let%lwt response =
    Hyper.run
    @@ Hyper.request ~method_:`GET ~headers (Uri.to_string uri)
  in
  handle response

let parse_json data f =
  match Yojson.Basic.from_string data with
  | exception Yojson.Json_error _ ->
    (* TODO Should bodies be logged? *)
    log.debug (fun log -> log "error parsing response json body=%s" data);
    Error "error parsing json response body"
  | json -> (
    try f json
    with Yojson.Basic.Util.Type_error _ | Yojson.Safe.Util.Type_error _ ->
      log.debug (fun log -> log "error parsing response json body=%s" data);
      Error "error parsing json response body")

let parse_json_body response f =
  let%lwt body = Dream_pure.Message.body response in
  Lwt.return (parse_json body f)
