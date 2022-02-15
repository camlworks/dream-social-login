let json_string_field key json =
  Yojson.Basic.Util.(
    try Ok (to_string (member key json))
    with Type_error _ ->
      Error
        (Printf.sprintf "error decoding JSON: missing or invalid `%s` field" key))

module User_profile = struct
  type t = { user : string; email : string }
  (** Information about an authenticated user.

      The fields choosen to be available from most of the OIDC providers. *)

  let to_json_string { user; email } =
    let json = `Assoc [ ("user", `String user); ("email", `String email) ] in
    Yojson.Basic.to_string json

  let of_json_string data =
    Result.bind
      (try Ok (Yojson.Basic.from_string data)
       with Yojson.Json_error error -> Error error)
    @@ fun json ->
    match (json_string_field "user" json, json_string_field "email" json) with
    | Ok user, Ok email -> Ok { user; email }
    | Error err, _ | _, Error err -> Error err
end

(* XXX: should be added by Hyper? *)
let user_agent = "hyper/1.0.0"
let log = Dream.sub_log "dream-oauth2"

module Github_provider = struct
  (** [authorize_url] is used to produce a URL to redirect browser to for
      authentication flow. *)
  let authorize_url ~client_id ~redirect_uri ~state ?(scope = [ "read:user" ])
      () =
    let params =
      Hyper.to_form_urlencoded
        [
          ("client_id", client_id);
          ("redirect_uri", redirect_uri);
          ("state", state);
          (* XXX: empty scope? *)
          ("scope", String.concat " " scope);
        ]
    in
    "https://github.com/login/oauth/authorize?" ^ params

  (** [access_token] performs a request to acquire an access_token. *)
  let access_token ~client_id ~client_secret ~code () =
    log.debug (fun log -> log "getting access_token");
    let%lwt resp =
      let body =
        Dream_pure.Formats.to_form_urlencoded
          [
            ("client_id", client_id);
            ("client_secret", client_secret);
            ("code", code);
          ]
      in
      Hyper.run
      @@ Hyper.request "https://github.com:443/login/oauth/access_token"
           ~method_:`POST
           ~body:(Dream_pure.Stream.string body)
           ~headers:
             [
               ("Host", "github.com");
               ("Accept", "*/*");
               ("User-Agent", user_agent);
               ("Content-Type", "application/x-www-form-urlencoded");
               (* XXX: should be added by hyper? *)
               ("Content-Length", Int.to_string (String.length body));
             ]
    in
    let%lwt body = Dream_pure.Message.body resp in
    match Dream_pure.Message.status resp with
    | #Dream_pure.Status.successful ->
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
    | status ->
        let status = Dream_pure.Status.status_to_string status in
        log.debug (fun log ->
            log "access_token response status=%s body=%s" status body);
        Lwt.return_error ("response status code: " ^ status)

  (** [user_profile] performs a request to get user profile info. *)
  let user_profile ~access_token () =
    log.debug (fun log -> log "getting user_profile");
    let exception User_profile_error of string in
    try%lwt
      let%lwt resp =
        Hyper.run
        @@ Hyper.request "https://api.github.com:443/user" ~method_:`GET
             ~headers:
               [
                 ("Authorization", "token " ^ access_token);
                 ("Host", "api.github.com");
                 ("Accept", "application/json");
                 ("User-Agent", user_agent);
               ]
      in
      let%lwt body = Dream_pure.Message.body resp in
      match Dream_pure.Message.status resp with
      | #Dream_pure.Status.successful ->
          let json =
            try Yojson.Basic.from_string body
            with Yojson.Json_error _ ->
              log.debug (fun log -> log "user_profile response body=%s" body);
              raise (User_profile_error "error parsing JSON response")
          in
          let json_string_field key json =
            match json_string_field key json with
            | Ok v -> v
            | Error err ->
                log.debug (fun log -> log "user_profile response body=%s" body);
                raise (User_profile_error err)
          in
          let user = json_string_field "login" json in
          let email = json_string_field "email" json in
          Lwt.return_ok { User_profile.user; email }
      | status ->
          let status = Dream_pure.Status.status_to_string status in
          log.debug (fun log ->
              log "user_profile response status=%s body=%s" status body);
          let reason = "response status code: " ^ status in
          raise (User_profile_error reason)
    with User_profile_error reason -> Lwt.return_error reason
end

module State_nonce_cookie = struct
  let cookie_name = "oauth2_state_nonce"

  let set res req state =
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~max_age:(60.0 *. 5.0) ~encrypt:true res req cookie_name state

  let get req = Dream.cookie ~decrypt:true req cookie_name
  let drop res req = Dream.drop_cookie ~http_only:true res req cookie_name
end

module User_profile_cookie = struct
  let cookie_name = "oauth2_user_profile"

  let set res req user_profile =
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~max_age:(60.0 *. 5.0) ~encrypt:true res req cookie_name
      (User_profile.to_json_string user_profile)

  let get req =
    Option.bind (Dream.cookie ~decrypt:true req cookie_name) @@ fun value ->
    match User_profile.of_json_string value with
    | Ok user_profile -> Some user_profile
    | Error _ -> None

  let drop res req = Dream.drop_cookie ~http_only:true res req cookie_name
end

let user_profile = User_profile_cookie.get

let route ~client_id ~client_secret ~redirect_uri ?(redirect_on_signin = "/")
    ?(redirect_on_signout = "/") () =
  Dream.scope "/" []
    [
      Dream.get "/oauth2/signin" (fun req ->
          let state = Dream.random 32 |> Dream.to_base64url in
          let url =
            Github_provider.authorize_url ~client_id ~redirect_uri ~state ()
          in
          let%lwt res = Dream.redirect req url in
          State_nonce_cookie.set res req state;
          Lwt.return res);
      Dream.get "/oauth2/signout" (fun req ->
          let%lwt res = Dream.redirect req redirect_on_signout in
          User_profile_cookie.drop res req;
          Lwt.return res);
      Dream.get "/oauth2/callback" (fun req ->
          let exception Callback_error of string in
          let error reason = raise (Callback_error reason) in
          try%lwt
            let%lwt res_ok = Dream.redirect req redirect_on_signin in
            let () =
              match Dream.query req "error" with
              | None -> ()
              | Some reason -> error ("provider returned: " ^ reason)
            in
            let () =
              let expected =
                match State_nonce_cookie.get req with
                | Some v ->
                    State_nonce_cookie.drop res_ok req;
                    v
                | None ->
                    error
                      "no callback request expected: `state` parameter missing"
              in
              let got =
                match Dream.query req "state" with
                | Some v -> v
                | None -> error "no `state` parameter in callback request"
              in
              if not (String.equal expected got) then
                error "`state` parameter mismatch"
            in
            let code =
              match Dream.query req "code" with
              | Some v -> v
              | None -> error "no `code` parameter in callback request"
            in
            let%lwt access_token =
              match%lwt
                Github_provider.access_token ~client_id ~client_secret ~code ()
              with
              | Ok access_token -> Lwt.return access_token
              | Error err -> error ("error getting access_token: " ^ err)
            in
            let%lwt user_profile =
              match%lwt Github_provider.user_profile ~access_token () with
              | Ok user_profile -> Lwt.return user_profile
              | Error reason -> error ("error getting user_profle: " ^ reason)
            in
            User_profile_cookie.set res_ok req user_profile;
            Lwt.return res_ok
          with Callback_error reason ->
            log.error (fun log -> log "Callback error: %s" reason);
            Dream.respond ~status:`Unauthorized "Failed to sign-in with GitHub");
    ]
