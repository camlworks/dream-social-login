let log = Dream.sub_log "dream-oauth2-stackoverflow"

type config = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
  key : string;
}

let authorize_endpoint = Uri.of_string "https://stackoverflow.com/oauth"

let token_endpoint =
  Uri.of_string "https://stackoverflow.com/oauth/access_token"

let userinfo_endpoint = Uri.of_string "https://api.stackexchange.com/2.3/me"

let authorize_url config req =
  authorize_endpoint
  |> Uri.with_uri
       ~query:
         (Some
            [
              ("client_id", [config.client_id]);
              ("redirect_uri", [config.redirect_uri]);
              ("state", [Dream.csrf_token req]);
            ])
  |> Uri.to_string

let access_token config _request ~code =
  log.debug (fun log -> log "getting access_token");
  let%lwt resp =
    Hyper_helper.post token_endpoint
      ~body:
        (`Form
          [
            ("client_id", config.client_id);
            ("client_secret", config.client_secret);
            ("code", code);
            ("redirect_uri", config.redirect_uri);
          ])
      ~headers:[("Accept", "*/*")]
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
    (Hyper_helper.get
       (Uri.with_uri userinfo_endpoint
          ~query:
            (Some
               [
                 ("access_token", [access_token]);
                 ("key", [config.key]);
                 ("site", ["stackoverflow"]);
               ]))
       ~headers:
         [
           ("Authorization", "token " ^ access_token);
           ("Accept", "application/json");
         ])
    (Hyper_helper.parse_json_body ~f:(fun json ->
         let open Yojson.Basic.Util in
         let user = json |> member "items" |> index 0 in
         Ok
           {
             Oauth2.User_profile.provider = "stackoverflow";
             id = user |> member "user_id" |> to_int |> Int.to_string;
             name = user |> member "display_name" |> to_string_option;
             email = None;
             email_verified = None;
             json;
           }))

let authenticate config =
  Oauth2.authenticate ~access_token:(access_token config)
    ~user_profile:(user_profile config)
