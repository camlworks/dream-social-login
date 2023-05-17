type client = {
  client_id : string;
  client_secret : string;
  redirect_uri : string;
  key : string;
}

let make ~client_id ~client_secret ~redirect_uri ~key = {
  client_id;
  client_secret;
  redirect_uri;
  key;
}

let authorize_endpoint =
  Uri.of_string "https://stackoverflow.com/oauth"

let token_endpoint =
  Uri.of_string "https://stackoverflow.com/oauth/access_token"

let userinfo_endpoint =
  Uri.of_string "https://api.stackexchange.com/2.3/me"

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
    "redirect_uri", client.redirect_uri;
  ]
  in
  let headers = [("Accept", "*/*")] in
  match%lwt Hyper_helper.post token_endpoint ~body ~headers with
  | Error _ as error -> Lwt.return error
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

let user_profile client _request ~access_token =
  let headers = [
    "Authorization", "token " ^ access_token;
    "Accept", "application/json";
  ]
  in
  let query = Some [
    "access_token", [access_token];
    "key", [client.key];
    "site", ["stackoverflow"];
  ]
  in
  let uri = Uri.with_uri userinfo_endpoint ~query in
  match%lwt Hyper_helper.get uri ~headers with
  | Error _ as error ->
    Lwt.return error
  | Ok response ->
    Hyper_helper.parse_json_body response @@ fun json ->
    let open Yojson.Basic.Util in
    let user = json |> member "items" |> index 0 in
    Ok {
      Oauth.User_profile.provider = "stackoverflow";
      id = user |> member "user_id" |> to_int |> Int.to_string;
      name = user |> member "display_name" |> to_string_option;
      email = None;
      email_verified = None;
      json;
    }

let authenticate client =
  Oauth.authenticate
    ~access_token:(access_token client) ~user_profile:(user_profile client)
