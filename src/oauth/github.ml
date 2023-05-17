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
  Uri.of_string "https://github.com/login/oauth/authorize"

let token_endpoint =
  Uri.of_string "https://github.com/login/oauth/access_token"

let userinfo_endpoint =
  Uri.of_string "https://api.github.com/user"

let authorize_url client request =
  let query = Some [
    "client_id", [client.client_id];
    "redirect_uri", [client.redirect_uri];
    "state", [Dream.csrf_token request];
  ]
  in
  authorize_endpoint
  |> Uri.with_uri ~query
  |> Uri.to_string

let access_token client _request ~code =
  let body = `Form [
    "client_id", client.client_id;
    "client_secret", client.client_secret;
    "code", code;
  ]
  in
  let headers = [("Accept", "*/*")] in
  match%lwt Hyper_helper.post token_endpoint ~body ~headers with
  | Error _ as error ->
    Lwt.return error
  | Ok response ->
    let%lwt body = Hyper.body response in
    let data = Dream.from_form_urlencoded body in
    let access_token =
      data |> List.find_map @@ function
        | "access_token", access_token -> Some access_token
        | _ -> None
    in
    match access_token with
    | Some token ->
      Lwt.return (Ok token)
    | None ->
      Lwt.return (Error "no 'access_token' in the response")

let user_profile _client _request ~access_token =
  let headers = [
    "Authorization", "token " ^ access_token;
    "Accept", "application/json";
  ]
  in
  match%lwt Hyper_helper.get userinfo_endpoint ~headers with
  | Error _ as error ->
    Lwt.return error
  | Ok response ->
    Hyper_helper.parse_json_body response @@ fun json ->
    let open Yojson.Basic.Util in
    let login = json |> member "login" |> to_string in
    let email = json |> member "email" |> to_string in
    Ok {
      Oauth.User_profile.provider = "github";
      id = login;
      name = Some login;
      email = Some email;
      email_verified = None;
      json;
    }

let authenticate client =
  Oauth.authenticate
    ~access_token:(access_token client) ~user_profile:(user_profile client)
