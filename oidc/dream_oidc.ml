module Hyper_helper = Dream_oauth2.Internal.Hyper_helper
module User_profile = Dream_oauth2.User_profile

type config = {
  client : Oidc.Client.t;
  provider_uri : Uri.t;
  redirect_uri : Uri.t;
  discovery : Oidc.Discover.t;
  jwks : Jose.Jwks.t;
  scope : string list;
  user_claims : string list;
}

let discover provider_uri =
  let open Lwt_result.Infix in
  let uri =
    let base_path = Uri.path provider_uri in
    provider_uri
    |> Uri.with_uri
         ~path:(Some (base_path ^ "/.well-known/openid-configuration"))
  in
  Hyper_helper.get uri ~headers:[("accept", "*/*")] >>= fun resp ->
  let%lwt body = Dream.body resp in
  Lwt.return_ok (Oidc.Discover.of_string body)

let jwks discovery =
  let open Lwt_result.Infix in
  Hyper_helper.get discovery.Oidc.Discover.jwks_uri >>= fun resp ->
  let%lwt body = Dream.body resp in
  Lwt.return_ok (Jose.Jwks.of_string body)

let configure ?(user_claims = []) ?(scope = []) ~client_id ~client_secret
    ~redirect_uri provider_uri =
  let redirect_uri = Uri.of_string redirect_uri in
  let provider_uri = Uri.of_string provider_uri in
  let client =
    Oidc.Client.make ~secret:client_secret ~response_types:["code"]
      ~grant_types:[] ~redirect_uris:[redirect_uri]
      ~token_endpoint_auth_method:"client_secret_post" client_id
  in
  let discovery =
    match Lwt_main.run (discover provider_uri) with
    | Ok discovery -> discovery
    | Error err -> failwith err
  in
  let () =
    match discovery.Oidc.Discover.userinfo_endpoint with
    | None -> failwith "missing userinfo_endpoint"
    | Some _ -> ()
  in
  let jwks =
    match Lwt_main.run (jwks discovery) with
    | Ok jwks -> jwks
    | Error err -> failwith err
  in
  { client; redirect_uri; provider_uri; discovery; jwks; scope; user_claims }

let google ?user_claims ?(scope = []) ~client_id ~client_secret ~redirect_uri ()
    =
  configure ?user_claims
    ~scope:("profile" :: "email" :: scope)
    ~client_id ~client_secret ~redirect_uri "https://accounts.google.com"

let microsoft ?user_claims ?(scope = []) ~client_id ~client_secret ~redirect_uri
    () =
  configure ?user_claims
    ~scope:("profile" :: "email" :: scope)
    ~client_id ~client_secret ~redirect_uri
    "https://login.microsoftonline.com/consumers/v2.0"

let twitch ?(user_claims = []) ?(scope = []) ~client_id ~client_secret
    ~redirect_uri () =
  let user_claims =
    "email" :: "email_verified" :: "preferred_username" :: user_claims
  in
  configure ~user_claims
    ~scope:("user:read:email" :: scope)
    ~client_id ~client_secret ~redirect_uri "https://id.twitch.tv/oauth2"

let authorize_url config req =
  let query =
    let scope = "openid" :: config.scope in
    let claims =
      match config.user_claims with
      | [] -> None
      | user_claims ->
        Some
          (`Assoc
            [
              ( "userinfo",
                `Assoc (List.map (fun claim -> (claim, `Null)) user_claims) );
            ])
    in
    Oidc.Parameters.make ?claims ~scope config.client
      ~state:(Dream.csrf_token req) ~nonce:(Dream.csrf_token req)
      ~redirect_uri:config.redirect_uri
    |> Oidc.Parameters.to_query
  in
  config.discovery.Oidc.Discover.authorization_endpoint
  |> Uri.with_uri ~query:(Some query)
  |> Uri.to_string

type id_token = {
  iss : string;
  sub : string;
  nonce : string;
}

(* Extract and validate id_token. *)
let id_token config token =
  let ( >>= ) = Result.bind in
  Jose.Jwt.of_string token.Oidc.Token.Response.id_token
  >>= (fun jwt ->
        (* We always use `nonce` (as CSRF tag) but we don't store it
           anywhere, we only check that the the `nonce` in token belongs to the
           current session (see authenticate function).

           So here we extract the `nonce` from jwt and pass it to validation so
           validation doesn't fail. *)
        (match Yojson.Safe.Util.member "nonce" jwt.payload with
        | `String nonce -> Ok nonce
        | _ -> Error `Missing_nonce)
        >>= fun nonce ->
        Oidc.Token.Response.validate ~nonce ~jwks:config.jwks
          ~client:config.client ~discovery:config.discovery token
        >>= fun _ -> Ok (jwt, nonce))
  |> Result.map_error (fun err ->
         "error validating id_token: "
         ^ Oidc.IDToken.validation_error_to_string err)
  >>= fun (jwt, nonce) ->
  Hyper_helper.parse_json jwt.Jose.Jwt.raw_payload ~f:(fun json ->
      let open Yojson.Basic.Util in
      Ok
        {
          iss = json |> member "iss" |> to_string;
          sub = json |> member "sub" |> to_string;
          nonce;
        })

(* Fetch and validate tokens (access_token and id_token). *)
let token config ~code =
  let open Lwt_result.Infix in
  let body =
    Oidc.Token.Request.make ~client:config.client
      ~grant_type:"authorization_code" ~scope:["openid"]
      ~redirect_uri:config.redirect_uri ~code
    |> Oidc.Token.Request.to_body_string
  in
  let headers =
    [
      ("Content-Type", "application/x-www-form-urlencoded");
      ("Accept", "application/json");
    ]
  in
  let headers =
    match config.client.token_endpoint_auth_method with
    | "client_secret_basic" ->
      Oidc.Token.basic_auth ~client_id:config.client.id
        ~secret:(Option.value ~default:"" config.client.secret)
      :: headers
    | _ -> headers
  in
  Hyper_helper.post config.discovery.Oidc.Discover.token_endpoint
    ~body:(`String body) ~headers
  >>= fun resp ->
  let%lwt body = Dream.body resp in
  match Oidc.Token.Response.of_string body with
  | exception Yojson.Json_error _ ->
    Lwt.return_error "error parsing token payload"
  | token -> (
    Lwt.return (id_token config token) >>= fun id_token ->
    match token.Oidc.Token.Response.access_token with
    | Some access_token -> Lwt.return_ok (access_token, id_token)
    | None -> Lwt.return_error "missing access_token")

let user_profile config ~access_token ~id_token =
  let open Lwt_result.Infix in
  let userinfo_endpoint =
    match config.discovery.userinfo_endpoint with
    | None -> assert false (* checked in configure *)
    | Some userinfo_endpoint -> userinfo_endpoint
  in
  Hyper_helper.get userinfo_endpoint
    ~headers:
      [
        ("Authorization", "Bearer " ^ access_token);
        ("Accept", "application/json");
      ]
  >>= Hyper_helper.parse_json_body ~f:(fun json ->
          let open Yojson.Basic.Util in
          let sub = member "sub" json |> to_string in
          if String.equal sub id_token.sub then
            let name =
              match member "name" json with
              | `Null -> member "preferred_username" json |> to_string_option
              | json -> to_string_option json
            in
            Ok
              {
                Dream_oauth2.User_profile.provider = id_token.iss;
                id = sub;
                name;
                email = member "email" json |> to_string_option;
                email_verified = member "email_verified" json |> to_bool_option;
                json;
              }
          else
            Error "invalid user_profile")

type authenticate_result = Dream_oauth2.authenticate_result

let authenticate config req =
  let exception Return of authenticate_result in
  let errorf fmt =
    let kerr message = raise (Return (`Error message)) in
    Printf.ksprintf kerr fmt
  in
  try%lwt
    let () =
      match Dream.query req "error" with
      | None -> ()
      | Some err -> (
        match Dream_oauth2.provider_error_of_string err with
        | Some err ->
          let desc = Dream.query req "error_description" in
          raise (Return (`Provider_error (err, desc)))
        | None -> errorf "provider returned unknown error code: %s" err)
    in
    let%lwt () =
      let state =
        match Dream.query req "state" with
        | Some v -> v
        | None -> errorf "no `state` parameter in callback request"
      in
      match%lwt Dream.verify_csrf_token req state with
      | `Ok -> Lwt.return ()
      | `Expired _ | `Wrong_session -> raise (Return `Expired)
      | `Invalid -> errorf "invalid `state` parameter"
    in
    let code =
      match Dream.query req "code" with
      | Some v -> v
      | None -> errorf "no `code` parameter in callback request"
    in
    let%lwt access_token, id_token =
      match%lwt token config ~code with
      | Ok tokens -> Lwt.return tokens
      | Error err -> errorf "error getting access_token: %s" err
    in
    let%lwt () =
      match%lwt Dream.verify_csrf_token req id_token.nonce with
      | `Ok -> Lwt.return ()
      | `Expired _ | `Wrong_session -> raise (Return `Expired)
      | `Invalid -> errorf "invalid `nonce` parameter"
    in
    let%lwt user_profile =
      match%lwt user_profile config ~access_token ~id_token with
      | Ok user_profile -> Lwt.return user_profile
      | Error err -> errorf "error getting user_profile: %s" err
    in
    Lwt.return (`Ok user_profile)
  with Return result -> Lwt.return result
