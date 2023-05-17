type client = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
}

let make ~client_id ~client_secret ~redirect_uri = {
  client_id;
  client_secret;
  redirect_uri;
}

let authorize_endpoint =
  Uri.of_string "https://id.twitch.tv/oauth2/authorize"

let token_endpoint =
  Uri.of_string "https://id.twitch.tv/oauth2/token"

let userinfo_endpoint =
  Uri.of_string "https://api.twitch.tv/helix/users"

let authorize_url client request =
  let query = Some [
    "client_id", [client.client_id];
    "redirect_uri", [client.redirect_uri];
    "state", [Dream.csrf_token request];
    "scope", ["user:read:email"];
    "response_type", ["code"];
  ]
  in
  authorize_endpoint
  |> Uri.with_uri ~query
  |> Uri.to_string

let access_token client _request ~code =
  let body = `Form [
    ("client_id", client.client_id);
    ("client_secret", client.client_secret);
    ("code", code);
    ("grant_type", "authorization_code");
    ("redirect_uri", client.redirect_uri);
  ]
  in
  let headers = ["Accept", "application/json"] in
  match%lwt Hyper_helper.post token_endpoint ~body ~headers with
  | Error _ as error ->
    Lwt.return error
  | Ok response ->
    Hyper_helper.parse_json_body response @@ fun json ->
    let access_token =
      Yojson.Basic.Util.(json |> member "access_token" |> to_string) in
    Ok access_token

let user_profile client _request ~access_token =
  let headers = [
    "Authorization", "Bearer " ^ access_token;
    "Client-id", client.client_id;
    "Accept", "application/json";
  ]
  in
  match%lwt Hyper_helper.get userinfo_endpoint ~headers with
  | Error _ as error -> Lwt.return error
  | Ok body ->
    Hyper_helper.parse_json_body body @@ fun json ->
    let open Yojson.Basic.Util in
    let user = json |> member "data" |> index 0 in
    Ok {
      Oauth.User_profile.provider = "twitch";
      id = user |> member "login" |> to_string;
      name = user |> member "display_name" |> to_string_option;
      email = user |> member "email" |> to_string_option;
      email_verified = None;
      json;
    }

let authenticate client =
  Oauth.authenticate
    ~access_token:(access_token client) ~user_profile:(user_profile client)
