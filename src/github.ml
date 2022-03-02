let log = Dream.sub_log "dream-oauth2-github"

type config = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
}

let name = "github"

(** [authorize_url] is used to produce a URL to redirect browser to for
      authentication flow. *)
let authorize_url ~state config =
  Hyper_helper.url "https://github.com/login/oauth/authorize"
    ~params:
      [
        ("client_id", config.client_id);
        ("redirect_uri", config.redirect_uri);
        ("state", state);
      ]

(** [access_token] performs a request to acquire an access_token. *)
let access_token ~code config =
  log.debug (fun log -> log "getting access_token");
  let%lwt resp =
    Hyper_helper.post "https://github.com:443/login/oauth/access_token"
      ~body:
        (`Form
          [
            ("client_id", config.client_id);
            ("client_secret", config.client_secret);
            ("code", code);
          ])
      ~headers:[("Host", "github.com"); ("Accept", "*/*")]
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

(** [user_profile] performs a request to get user profile info. *)
let user_profile ~access_token _config =
  log.debug (fun log -> log "getting user_profile");
  Lwt_result.bind
    (Hyper_helper.get "https://api.github.com:443/user"
       ~headers:
         [
           ("Authorization", "token " ^ access_token);
           ("Host", "api.github.com");
           ("Accept", "application/json");
         ])
    (Hyper_helper.parse_json_body ~f:(fun json ->
         let open Yojson.Basic.Util in
         let login = json |> member "login" |> to_string in
         let email = json |> member "email" |> to_string in
         Ok
           {
             Oauth2.User_profile.id = login;
             display_name = login;
             email = Some email;
             provider = name;
           }))
