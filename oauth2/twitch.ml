let log = Dream.sub_log "dream-oauth2-twitch"

type config = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
}

let authorize_endpoint = Uri.of_string "https://id.twitch.tv/oauth2/authorize"
let token_endpoint = Uri.of_string "https://id.twitch.tv/oauth2/token"
let userinfo_endpoint = Uri.of_string "https://api.twitch.tv/helix/users"

let authorize_url config request =
  authorize_endpoint
  |> Uri.with_uri
       ~query:
         (Some
            [
              ("client_id", [config.client_id]);
              ("redirect_uri", [config.redirect_uri]);
              ("state", [Dream.csrf_token request]);
              ("scope", ["user:read:email"]);
              ("response_type", ["code"]);
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
            ("grant_type", "authorization_code");
            ("redirect_uri", config.redirect_uri);
          ])
      ~headers:[("Accept", "application/json")]
  in
  match resp with
  | Ok resp ->
    Hyper_helper.parse_json_body resp ~f:(fun json ->
        let access_token =
          Yojson.Basic.Util.(json |> member "access_token" |> to_string)
        in
        Ok access_token)
  | Error err -> Lwt.return_error err

let user_profile config _request ~access_token =
  log.debug (fun log -> log "getting user_profile");
  Lwt_result.bind
    (Hyper_helper.get userinfo_endpoint
       ~headers:
         [
           ("Authorization", "Bearer " ^ access_token);
           ("Client-id", config.client_id);
           ("Accept", "application/json");
         ])
    (Hyper_helper.parse_json_body ~f:(fun json ->
         let open Yojson.Basic.Util in
         let user = json |> member "data" |> index 0 in
         Ok
           {
             Oauth2.User_profile.id = user |> member "login" |> to_string;
             display_name = user |> member "display_name" |> to_string;
             email = Some (user |> member "email" |> to_string);
             provider = "twitch";
           }))

let authenticate config =
  Oauth2.authenticate ~access_token:(access_token config)
    ~user_profile:(user_profile config)
