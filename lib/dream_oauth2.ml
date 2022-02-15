(* TODO: expose it interface *)
module User_profile = struct
  type t = { user : string; email : string }
end

(* XXX: should be added by Hyper? *)
let user_agent = "hyper/1.0.0"

module Github_provider = struct
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

  let access_token ~client_id ~client_secret ~code () =
    let body =
      Dream_pure.Formats.to_form_urlencoded
        [
          ("client_id", client_id);
          ("client_secret", client_secret);
          ("code", code);
        ]
    in
    let%lwt resp =
      Hyper.post
        ~headers:
          [
            ("Host", "github.com");
            ("Accept", "*/*");
            ("User-Agent", user_agent);
            ("Content-Type", "application/x-www-form-urlencoded");
            (* XXX: should be added by hyper? *)
            ("Content-Length", Int.to_string (String.length body));
          ]
        "https://github.com:443/login/oauth/access_token" body
    in
    let data = Dream_pure.Formats.from_form_urlencoded resp in
    Lwt.return
      (ListLabels.find_map data ~f:(function
        | "access_token", access_token -> Some access_token
        | _ -> None))

  let user_profile ~access_token () =
    let%lwt data =
      Hyper.get "https://api.github.com:443/user"
        ~headers:
          [
            ("Authorization", "token " ^ access_token);
            ("Host", "api.github.com");
            ("Accept", "application/json");
            ("User-Agent", user_agent);
          ]
    in
    let user_profile =
      (* XXX: handle parse error *)
      let json = Yojson.Basic.from_string data in
      (* XXX: handle Yojson.Basic.Util.Type_error *)
      Yojson.Basic.Util.
        {
          User_profile.user = member "login" json |> to_string;
          email = member "email" json |> to_string;
        }
    in
    Lwt.return user_profile
end

(* TODO: research if using Same-Site: Lax is ok here, alternatively there's
   client side redirect. *)
module State_nonce_cookie = struct
  let cookie_name = "oauth2_state_nonce"

  let set res req state =
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~max_age:(60.0 *. 5.0) ~encrypt:true res req cookie_name state

  let get req = Dream.cookie ~decrypt:true req cookie_name
  let drop res req = Dream.drop_cookie ~http_only:true res req cookie_name
end

(* TODO: we should use session mechanism here, research why it doesn't work for
   me. *)
module Auth_cookie = struct
  let cookie_name = "oauth2_auth"

  let set res req state =
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~max_age:(60.0 *. 5.0) ~encrypt:true res req cookie_name state

  let get req = Dream.cookie ~decrypt:true req cookie_name
  let drop res req = Dream.drop_cookie ~http_only:true res req cookie_name
end

(* TODO: this should return [User_profile.t] instead of just username. *)
let user_profile = Auth_cookie.get

(* TODO: should we make [redirect_uri] optional? *)
let route ~client_id ~client_secret ~redirect_uri () =
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
          let%lwt res = Dream.redirect req "/" in
          Auth_cookie.drop res req;
          Lwt.return res);
      Dream.get "/oauth2/callback" (fun req ->
          (* TODO: error handling *)
          let exception Oauth2_callback_failure of string in
          try%lwt
            let%lwt res_ok = Dream.redirect req "/" in
            let () =
              let expected =
                match State_nonce_cookie.get req with
                | None -> raise (Oauth2_callback_failure "no state in session")
                | Some v ->
                    State_nonce_cookie.drop res_ok req;
                    v
              in
              let got =
                match Dream.query req "state" with
                | None -> raise (Oauth2_callback_failure "no state in request")
                | Some v -> v
              in
              if not (String.equal expected got) then
                raise (Oauth2_callback_failure "state mismatch")
            in
            Dream.info (fun log -> log "state validated");
            let code =
              match Dream.query req "code" with
              | None -> raise (Oauth2_callback_failure "no code in request")
              | Some v -> v
            in
            Dream.info (fun log -> log "getting access_token");
            let%lwt access_token =
              match%lwt
                Github_provider.access_token ~client_id ~client_secret ~code ()
              with
              | None -> raise (Oauth2_callback_failure "missing access_token")
              | Some access_token -> Lwt.return access_token
            in
            Dream.info (fun log -> log "getting user_profile");
            let%lwt user_profile =
              Github_provider.user_profile ~access_token ()
            in
            Auth_cookie.set res_ok req user_profile.User_profile.user;
            Lwt.return res_ok
          with Oauth2_callback_failure reason ->
            Dream.error (fun log -> log "OAuth2 failure: %s" reason);
            Dream.redirect req "/");
    ]
