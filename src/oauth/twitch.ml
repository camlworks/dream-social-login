let log = Dream.sub_log "dream-oauth2-twitch"

type oauth2 = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
}

let make ~client_id ~client_secret ~redirect_uri () =
  { client_id; client_secret; redirect_uri }

let authorize_endpoint = Uri.of_string "https://id.twitch.tv/oauth2/authorize"
let token_endpoint = Uri.of_string "https://id.twitch.tv/oauth2/token"
let userinfo_endpoint = Uri.of_string "https://api.twitch.tv/helix/users"

let authorize_url oauth2 request =
  authorize_endpoint
  |> Uri.with_uri
       ~query:
         (Some
            [
              ("client_id", [oauth2.client_id]);
              ("redirect_uri", [oauth2.redirect_uri]);
              ("state", [Dream.csrf_token request]);
              ("scope", ["user:read:email"]);
              ("response_type", ["code"]);
            ])
  |> Uri.to_string

let access_token oauth2 _request ~code =
  log.debug (fun log -> log "getting access_token");
  let%lwt resp =
    Hyper_helper.post token_endpoint
      ~body:
        (`Form
          [
            ("client_id", oauth2.client_id);
            ("client_secret", oauth2.client_secret);
            ("code", code);
            ("grant_type", "authorization_code");
            ("redirect_uri", oauth2.redirect_uri);
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

let user_profile oauth2 _request ~access_token =
  log.debug (fun log -> log "getting user_profile");
  Lwt_result.bind
    (Hyper_helper.get userinfo_endpoint
       ~headers:
         [
           ("Authorization", "Bearer " ^ access_token);
           ("Client-id", oauth2.client_id);
           ("Accept", "application/json");
         ])
    (Hyper_helper.parse_json_body ~f:(fun json ->
         let open Yojson.Basic.Util in
         let user = json |> member "data" |> index 0 in
         Ok
           {
             Oauth.User_profile.provider = "twitch";
             id = user |> member "login" |> to_string;
             name = user |> member "display_name" |> to_string_option;
             email = user |> member "email" |> to_string_option;
             email_verified = None;
             json;
           }))

let authenticate oauth2 =
  Oauth.authenticate ~access_token:(access_token oauth2)
    ~user_profile:(user_profile oauth2)
