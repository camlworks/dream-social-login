let log = Dream.sub_log "dream-oauth2-github"

type config = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
}

let authorize_endpoint =
  Uri.of_string "https://github.com/login/oauth/authorize"

let token_endpoint = Uri.of_string "https://github.com/login/oauth/access_token"
let userinfo_endpoint = Uri.of_string "https://api.github.com/user"

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

let access_token config _req ~code =
  log.debug (fun log -> log "getting access_token");
  Lwt_result.bind
    (Hyper_helper.post token_endpoint
       ~body:
         (`Form
           [
             ("client_id", config.client_id);
             ("client_secret", config.client_secret);
             ("code", code);
           ])
       ~headers:[("Accept", "*/*")])
    (fun resp ->
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
          Error "no `access_token` in the response"))

let user_profile _config _req ~access_token =
  log.debug (fun log -> log "getting user_profile");
  Lwt_result.bind
    (Hyper_helper.get userinfo_endpoint
       ~headers:
         [
           ("Authorization", "token " ^ access_token);
           ("Accept", "application/json");
         ])
    (Hyper_helper.parse_json_body ~f:(fun json ->
         let open Yojson.Basic.Util in
         let login = json |> member "login" |> to_string in
         let email = json |> member "email" |> to_string in
         Ok
           {
             Oauth2.User_profile.provider = "github";
             id = login;
             name = Some login;
             email = Some email;
             email_verified = None;
             json;
           }))

let authenticate config =
  Oauth2.authenticate ~access_token:(access_token config)
    ~user_profile:(user_profile config)
