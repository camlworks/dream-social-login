module Hyper_helper = Dream_oauth.Internal.Hyper_helper
module User_profile = Dream_oauth.User_profile

type client = {
  client : Oidc.Client.t;
  provider_uri : Uri.t;
  redirect_uri : Uri.t;
  scope : string list;
  user_claims : string list;
  mutable config : (config, string) result Lwt.t;
}

and config = {
  discovery : Oidc.Discover.t;
  jwks : Jose.Jwks.t;
}

let provider_uri client =
  Uri.to_string client.provider_uri

let discover provider_uri =
  let uri =
    let base_path = Uri.path provider_uri in
    provider_uri
    |> Uri.with_uri
      ~path:(Some (base_path ^ "/.well-known/openid-configuration"))
  in
  match%lwt Hyper_helper.get uri ~headers:[("accept", "*/*")] with
  | Error _ as error ->
    Lwt.return error
  | Ok response ->
    let%lwt body = Dream.body response in
    Lwt.return (Ok (Oidc.Discover.of_string body))

let jwks discovery =
  match%lwt Hyper_helper.get discovery.Oidc.Discover.jwks_uri with
  | Error _ as error ->
    Lwt.return error
  | Ok response ->
    let%lwt body = Dream.body response in
    Lwt.return (Ok (Jose.Jwks.of_string body))

let make
    ?(user_claims = []) ?(scope = []) ~client_id ~client_secret ~redirect_uri
    provider_uri =
  let redirect_uri = Uri.of_string redirect_uri in
  let provider_uri = Uri.of_string provider_uri in
  let client =
    Oidc.Client.make
      ~secret:client_secret ~response_types:["code"] ~grant_types:[]
      ~redirect_uris:[redirect_uri]
      ~token_endpoint_auth_method:"client_secret_post" client_id
  in
  {
    client;
    redirect_uri;
    provider_uri;
    scope;
    user_claims;
    config =
      (* Put error here so we'll fail if user didn't call [configure]. *)
      Lwt.return_error
        "OIDC client is not configured: forgot to call configure?";
  }

let configure client =
  let config_promise =
    match%lwt discover client.provider_uri with
    | Error _ as error ->
      Lwt.return error
    | Ok (Error _) ->
      Lwt.return (Error "OIDC discovery error (details TODO)")
    | Ok (Ok discovery) ->
      match%lwt jwks discovery with
      | Error _ as error ->
        Lwt.return error
      | Ok jwks ->
        match discovery.Oidc.Discover.userinfo_endpoint with
        | None -> Lwt.return (Error "OIDC discovery missing userinfo_endpoint")
        | Some _ -> Lwt.return (Ok {discovery; jwks})
  in

  client.config <- config_promise;
  match%lwt config_promise with
  | Error _ as error ->
    Lwt.return error
  | Ok _ ->
    Lwt.return (Ok ())

let authorize_url client request =
  let query =
    let scope = List.map Oidc.Scopes.of_string ("openid"::client.scope) in
    let claims =
      match client.user_claims with
      | [] ->
        None
      | user_claims ->
        Some (`Assoc [
          "userinfo",
          `Assoc (List.map (fun claim -> (claim, `Null)) user_claims);
        ])
    in
    Oidc.Parameters.make
      ?claims ~scope ~client_id:client.client.Oidc.Client.id
      ~state:(Dream.csrf_token request) ~nonce:(Dream.csrf_token request)
      ~redirect_uri:client.redirect_uri ()
    |> Oidc.Parameters.to_query
  in
  match%lwt client.config with
  | Error _ as error ->
    Lwt.return error
  | Ok config ->
    config.discovery.Oidc.Discover.authorization_endpoint
    |> Uri.with_uri ~query:(Some query)
    |> Uri.to_string
    |> Lwt.return_ok

module Id_token =
struct
  type id_token = {
    iss : string;
    sub : string;
    nonce : string;
  }

  let of_token_response ~discovery ~jwks ~client token =
    let (>>=) = Result.bind in
    (* TODO This Option.get is based on usage upstream in ocaml-oidc. It's
       probably worth reviewing whether it is safe - it appears to be None only
       in providers, which this library does not implement. Replace this comment
       by an argument why this is ok. *)
    (* TODO Jose.Jwt.of_string had is signature changed in
       https://github.com/ulrikstrid/ocaml-jose/pull/37, which also added
       unsafe_of_string. We are now using unsafe_of_string just to get this
       building, but we should look into how to use of_string correctly, or
       whether it should be used. *)
    begin
    Jose.Jwt.unsafe_of_string (Option.get token.Oidc.Token.Response.id_token)
    >>= fun jwt ->
    (* We always use 'nonce' (as CSRF tag) but we don't store it anywhere, we
       only check that the the 'nonce' in token belongs to the current session
       (see authenticate function).

       So here we extract the `nonce` from jwt and pass it to validation so
       validation doesn't fail. *)
    begin match Yojson.Safe.Util.member "nonce" jwt.payload with
    | `String nonce -> Ok nonce
    | _ -> Error `Missing_nonce
    end
    >>= fun nonce ->
    Oidc.Token.Response.validate ~nonce ~jwks ~client ~discovery token
    >>= fun _ ->
    Ok (jwt, nonce)
    end
    |> Result.map_error (fun err ->
      "error validating id_token: " ^
      Oidc.IDToken.validation_error_to_string err)
    >>= fun (jwt, nonce) ->
    Hyper_helper.parse_json jwt.Jose.Jwt.raw_payload @@ fun json ->
    let open Yojson.Basic.Util in
    Ok {
      iss = json |> member "iss" |> to_string;
      sub = json |> member "sub" |> to_string;
      nonce;
    }
end

let token client ~code =
  let scope = [Oidc.Scopes.of_string "openid"] in
  let body =
    Oidc.Token.Request.make
      ~client:client.client ~grant_type:"authorization_code"
      ~scope ~redirect_uri:client.redirect_uri ~code
    |> Oidc.Token.Request.to_body_string
  in
  let headers = [
    "Content-Type", "application/x-www-form-urlencoded";
    "Accept", "application/json";
  ]
  in
  let headers =
    match client.client.token_endpoint_auth_method with
    | "client_secret_basic" ->
      Oidc.Token.basic_auth
        ~client_id:client.client.id
        ~secret:(Option.value ~default:"" client.client.secret)
      ::headers
    | _ ->
      headers
  in
  let open Lwt_result.Infix in
  client.config >>= fun config' ->
  Hyper_helper.post
    config'.discovery.Oidc.Discover.token_endpoint
    ~body:(`String body) ~headers
  >>= fun response ->
  let%lwt body = Dream.body response in
  match Oidc.Token.Response.of_string body with
  | exception Yojson.Json_error _ | Error _ ->
    (* TODO Does Oidc still raise exceptions here, or has error handling been
       completely converted to results? *)
    Lwt.return_error "error parsing token payload"
  | Ok token ->
    Lwt.return @@
      Id_token.of_token_response
        ~client:client.client ~jwks:config'.jwks
        ~discovery:config'.discovery token
    >>= fun id_token ->
    match token.Oidc.Token.Response.access_token with
    | Some access_token -> Lwt.return_ok (access_token, id_token)
    | None -> Lwt.return_error "missing access_token"

let user_profile client ~access_token ~id_token =
  match%lwt client.config with
  | Error _ as error ->
    Lwt.return error
  | Ok config' ->
    let userinfo_endpoint =
      match config'.discovery.userinfo_endpoint with
      | None -> assert false (* checked in configure *)
      | Some userinfo_endpoint -> userinfo_endpoint
    in
    let headers = [
      "Authorization", "Bearer " ^ access_token;
      "Accept", "application/json";
    ]
    in
    match%lwt Hyper_helper.get userinfo_endpoint ~headers with
    | Error _ as error ->
      Lwt.return error
    | Ok body ->
      Hyper_helper.parse_json_body body @@ fun json ->
      let open Yojson.Basic.Util in
      let sub = member "sub" json |> to_string in
      if String.equal sub id_token.Id_token.sub then
        let name =
          match member "name" json with
          | `Null -> member "preferred_username" json |> to_string_option
          | json -> to_string_option json
        in
        Ok {
          Dream_oauth.User_profile.provider = id_token.iss;
          id = sub;
          name;
          email = member "email" json |> to_string_option;
          email_verified = member "email_verified" json |> to_bool_option;
          json;
        }
      else
        Error "invalid user_profile"

type authenticate_result = Dream_oauth.authenticate_result
and provider_error = Dream_oauth.provider_error

let provider_error_of_string = Dream_oauth.provider_error_of_string
let provider_error_to_string = Dream_oauth.provider_error_to_string

let authenticate client request =
  let exception Return of authenticate_result in
  let errorf fmt =
    let kerr message = raise (Return (`Error message)) in
    Printf.ksprintf kerr fmt
  in

  try%lwt

    begin match Dream.query request "error" with
    | None ->
      ()
    | Some error ->
      match Dream_oauth.provider_error_of_string error with
      | Some error ->
        let description = Dream.query request "error_description" in
        raise (Return (`Provider_error (error, description)))
      | None ->
        errorf "provider returned unknown error code: %s" error
    end;

    let%lwt () =
      let state =
        match Dream.query request "state" with
        | Some v -> v
        | None -> errorf "no 'state' parameter in callback request"
      in
      match%lwt Dream.verify_csrf_token request state with
      | `Ok -> Lwt.return ()
      | `Expired _ | `Wrong_session -> raise (Return `Expired)
      | `Invalid -> errorf "invalid 'state' parameter"
    in

    let code =
      match Dream.query request "code" with
      | Some v -> v
      | None -> errorf "no 'code' parameter in callback request"
    in
    let%lwt access_token, id_token =
      match%lwt token client ~code with
      | Ok tokens -> Lwt.return tokens
      | Error error -> errorf "error getting access_token: %s" error
    in

    let%lwt () =
      match%lwt Dream.verify_csrf_token request id_token.nonce with
      | `Ok -> Lwt.return ()
      | `Expired _ | `Wrong_session -> raise (Return `Expired)
      | `Invalid -> errorf "invalid 'nonce' parameter"
    in

    let%lwt user_profile =
      match%lwt user_profile client ~access_token ~id_token with
      | Ok user_profile -> Lwt.return user_profile
      | Error error -> errorf "error getting user_profile: %s" error
    in

    Lwt.return (`Ok user_profile)

  with Return result ->
    Lwt.return result

let google
    ?user_claims ?(scope = []) ~client_id ~client_secret ~redirect_uri () =
  make
    ?user_claims ~scope:("profile"::"email"::scope) ~client_id ~client_secret
    ~redirect_uri "https://accounts.google.com"

let microsoft
    ?user_claims ?(scope = []) ~client_id ~client_secret ~redirect_uri () =
  make
    ?user_claims ~scope:("profile"::"email"::scope) ~client_id ~client_secret
    ~redirect_uri "https://login.microsoftonline.com/consumers/v2.0"

let twitch
    ?(user_claims = []) ?(scope = []) ~client_id ~client_secret ~redirect_uri
    () =
  let user_claims =
    "email"::"email_verified"::"preferred_username"::user_claims in
  make
    ~user_claims ~scope:("user:read:email" :: scope) ~client_id ~client_secret
    ~redirect_uri "https://id.twitch.tv/oauth2"
