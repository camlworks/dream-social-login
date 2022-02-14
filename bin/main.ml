(* XXX: should be added by Hyper? *)
let user_agent = "hyper/1.0.0"

module User_profile = struct
  type t = { user : string; email : string }
end

module Github_oauth2 = struct
  let authorize_url = Uri.of_string "https://github.com/login/oauth/authorize"

  let authorize_url ~client_id ~redirect_uri ~state ?(scope = [ "read:user" ])
      () =
    let query =
      [
        ("client_id", [ client_id ]);
        ("redirect_uri", [ redirect_uri ]);
        ("state", [ state ]);
        ("scope", [ String.concat " " scope ]);
      ]
    in
    Uri.with_uri authorize_url ~query:(Some query) |> Uri.to_string

  let access_token_url =
    Uri.of_string "https://github.com:443/login/oauth/access_token"

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
        ~server:(Hyper.run ~transport:`HTTPS)
        ~headers:
          [
            ("Host", "github.com");
            ("Accept", "*/*");
            ("User-Agent", user_agent);
            ("Content-Type", "application/x-www-form-urlencoded");
            (* XXX: should be added by hyper? *)
            ("Content-Length", Int.to_string (String.length body));
          ]
        (Uri.to_string access_token_url)
        body
    in
    let data = Dream_pure.Formats.from_form_urlencoded resp in
    Lwt.return
      (ListLabels.find_map data ~f:(function
        | "access_token", access_token -> Some access_token
        | _ -> None))

  let user_profile_url = Uri.of_string "https://api.github.com:443/user"

  let user_profile ~access_token () =
    let url = Uri.to_string user_profile_url in
    let%lwt data =
      Hyper.get url
        ~server:(Hyper.run ~transport:`HTTPS)
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

let client_id = Sys.getenv "OAUTH2_CLIENT_ID"
let client_secret = Sys.getenv "OAUTH2_CLIENT_SECRET"
let redirect_uri = Sys.getenv "OAUTH2_REDIRECT_URI"

module Oauth2_state_nonce = struct
  let cookie_name = "oauth2_state_nonce"

  let set res req state =
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~max_age:(60.0 *. 5.0) ~encrypt:true res req cookie_name state

  let get req = Dream.cookie ~decrypt:true req cookie_name
  let drop res req = Dream.drop_cookie ~http_only:true res req cookie_name
end

module Oauth2_auth = struct
  let cookie_name = "oauth2_auth"

  let set res req state =
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~max_age:(60.0 *. 5.0) ~encrypt:true res req cookie_name state

  let get req = Dream.cookie ~decrypt:true req cookie_name
  let drop res req = Dream.drop_cookie ~http_only:true res req cookie_name
end

let () =
  Dream.run ~adjust_terminal:false ?interface:(Sys.getenv_opt "INTERFACE")
  @@ Dream.logger @@ Dream.memory_sessions
  @@ Dream.router
       [
         Dream.get "/" (fun req ->
             match Oauth2_auth.get req with
             | None ->
                 Dream.respond "<p>Please <a href='/oauth2/signin'>sign in</a>!"
             | Some user ->
                 Dream.respond
                   (Printf.sprintf
                      {|
                      <p>Hello, %s!<p>
                      <p><a href='/oauth2/signout'>Sign out</a></p>
                      |}
                      user));
         Dream.get "/oauth2/signin" (fun req ->
             let state = Dream.random 32 |> Dream.to_base64url in
             let url =
               Github_oauth2.authorize_url ~client_id ~redirect_uri ~state ()
             in
             let%lwt res = Dream.redirect req url in
             Oauth2_state_nonce.set res req state;
             Lwt.return res);
         Dream.get "/oauth2/signout" (fun req ->
             let%lwt res = Dream.redirect req "/" in
             Oauth2_auth.drop res req;
             Lwt.return res);
         Dream.get "/oauth2/callback" (fun req ->
             let exception Oauth2_callback_failure of string in
             try%lwt
               let%lwt res_ok = Dream.redirect req "/" in
               let () =
                 let expected =
                   match Oauth2_state_nonce.get req with
                   | None ->
                       raise (Oauth2_callback_failure "no state in session")
                   | Some v ->
                       Oauth2_state_nonce.drop res_ok req;
                       v
                 in
                 let got =
                   match Dream.query req "state" with
                   | None ->
                       raise (Oauth2_callback_failure "no state in request")
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
                   Github_oauth2.access_token ~client_id ~client_secret ~code ()
                 with
                 | None ->
                     raise (Oauth2_callback_failure "missing access_token")
                 | Some access_token -> Lwt.return access_token
               in
               print_endline access_token;
               Dream.info (fun log -> log "getting user_profile");
               let%lwt user_profile =
                 Github_oauth2.user_profile ~access_token ()
               in
               Oauth2_auth.set res_ok req user_profile.User_profile.user;
               Lwt.return res_ok
             with Oauth2_callback_failure reason ->
               Dream.error (fun log -> log "OAuth2 failure: %s" reason);
               Dream.redirect req "/");
       ]
