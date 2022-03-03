let log = Dream.sub_log "dream-oauth2-stackoverflow"

type config = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
  key : string;
}

let authorize_url config req =
  Hyper_helper.url "https://stackoverflow.com/oauth"
    ~params:
      [
        ("client_id", config.client_id);
        ("redirect_uri", config.redirect_uri);
        ("state", Dream.csrf_token req);
      ]

let access_token config _request ~code =
  log.debug (fun log -> log "getting access_token");
  let%lwt resp =
    Hyper_helper.post "https://stackoverflow.com:443/oauth/access_token"
      ~body:
        (`Form
          [
            ("client_id", config.client_id);
            ("client_secret", config.client_secret);
            ("code", code);
            ("redirect_uri", config.redirect_uri);
          ])
      ~headers:[("Host", "stackoverflow.com"); ("Accept", "*/*")]
  in
  match resp with
  | Ok resp ->
    let%lwt body = Dream_pure.Message.body resp in
    let data = Dream_pure.Formats.from_form_urlencoded body in
    let access_token =
      ListLabels.find_map data ~f:(function
        | "access_token", access_token -> Some access_token
        | _ -> None)
    in
    Lwt.return
      (match access_token with
      | Some token -> Ok token
      | None ->
        log.debug (fun log -> log "access_token response body=%s" body);
        Error "no `access_token` in the response")
  | Error err -> Lwt.return_error err

let user_profile config _request ~access_token =
  log.debug (fun log -> log "getting user_profile");
  Lwt_result.bind
    (Hyper_helper.get "https://api.stackexchange.com:443/2.3/me"
       ~params:
         [
           ("access_token", access_token);
           ("key", config.key);
           ("site", "stackoverflow");
         ]
       ~headers:
         [
           ("Authorization", "token " ^ access_token);
           ("Host", "api.stackexchange.com");
           ("Accept", "application/json");
         ])
    (Hyper_helper.parse_json_body ~f:(fun json ->
         let open Yojson.Basic.Util in
         let user = json |> member "items" |> index 0 in
         Ok
           {
             Oauth2.User_profile.id =
               user |> member "user_id" |> to_int |> Int.to_string;
             display_name = user |> member "display_name" |> to_string;
             email = None;
             provider = "stackoverflow";
           }))
