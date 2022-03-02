let log = Dream.sub_log "dream-oauth2"

module User_profile = Oauth2.User_profile

type oauth2 = Oauth2.t

let github ~client_id ~client_secret ~redirect_uri () =
  Oauth2.Oauth2
    {
      config = { Github.client_id; client_secret; redirect_uri };
      provider = (module Github);
    }

let stackoverflow ~client_id ~client_secret ~redirect_uri ~key () =
  Oauth2.Oauth2
    {
      config = { Stackoverflow.client_id; client_secret; redirect_uri; key };
      provider = (module Stackoverflow);
    }

let twitch ~client_id ~client_secret ~redirect_uri () =
  Oauth2.Oauth2
    {
      config = { Twitch.client_id; client_secret; redirect_uri };
      provider = (module Twitch);
    }

let user_profile = Auth_cookie.get
let signout = Auth_cookie.drop

let signin_url ?(valid_for = 60. *. 60. *. 1. (* 1 hour *))
    (Oauth2.Oauth2 { config; provider = (module Provider) }) req =
  Provider.authorize_url config
    ~state:
      (Printf.sprintf "%s.%s" Provider.name (Dream.csrf_token ~valid_for req))

let signout_form ?(signout_url = "/oauth2/signout") req =
  Printf.sprintf
    {|<form method="POST" action="%s">
        %s
        <input type="submit" value="Sign out" />
      </form>|}
    signout_url (Dream.csrf_tag req)

let route ?(redirect_on_signin = "/") ?(redirect_on_signout = "/")
    ?(redirect_on_signin_expired = "/") ?(redirect_on_signout_expired = "/")
    providers =
  Dream.scope "/" []
    [
      Dream.post "/oauth2/signout" (fun req ->
          match%lwt Dream.form req with
          | `Ok _ ->
            let%lwt res = Dream.redirect req redirect_on_signout in
            Auth_cookie.drop res req;
            Lwt.return res
          | `Expired _ | `Wrong_session _ ->
            Dream.redirect req redirect_on_signout_expired
          | `Invalid_token _
          | `Missing_token _
          | `Many_tokens _
          | `Wrong_content_type ->
            Dream.respond ~status:`Unauthorized "Failed to sign-out");
      Dream.get "/oauth2/callback" (fun req ->
          let exception Callback_error of string * string option in
          let error ?redirect reason =
            raise (Callback_error (reason, redirect))
          in
          try%lwt
            let%lwt res_ok = Dream.redirect req redirect_on_signin in
            let () =
              match Dream.query req "error" with
              | None -> ()
              | Some reason -> error ("provider returned: " ^ reason)
            in
            let%lwt provider_name =
              let provider_name, token =
                match Dream.query req "state" with
                | Some v -> (
                  match StringLabels.split_on_char ~sep:'.' v with
                  | [provider_name; token] -> (provider_name, token)
                  | _ -> error "invalid `state` parameter in callback request")
                | None -> error "no `state` parameter in callback request"
              in
              let%lwt () =
                match%lwt Dream.verify_csrf_token req token with
                | `Ok -> Lwt.return ()
                | `Expired _ | `Wrong_session ->
                  error ~redirect:redirect_on_signin_expired
                    "expired `state` parameter"
                | `Invalid -> error "invalid `state` parameter"
              in
              Lwt.return provider_name
            in
            let (Oauth2.Oauth2 { provider = (module Provider); config }) =
              let found =
                List.find_opt
                  (fun provider ->
                    String.equal (Oauth2.name provider) provider_name)
                  providers
              in
              match found with
              | Some provider -> provider
              | None ->
                log.error (fun log ->
                    log "`state` parameter refers to unknown provider: %s"
                      provider_name);
                error "invalid `state` parameter"
            in
            let code =
              match Dream.query req "code" with
              | Some v -> v
              | None -> error "no `code` parameter in callback request"
            in
            let%lwt access_token =
              match%lwt Provider.access_token config ~code with
              | Ok access_token -> Lwt.return access_token
              | Error err -> error ("error getting access_token: " ^ err)
            in
            let%lwt user_profile =
              match%lwt Provider.user_profile ~access_token config with
              | Ok user_profile -> Lwt.return user_profile
              | Error reason -> error ("error getting user_profile: " ^ reason)
            in
            Auth_cookie.set res_ok req user_profile;
            Lwt.return res_ok
          with Callback_error (reason, redirect) -> (
            log.error (fun log -> log "Callback error: %s" reason);
            match redirect with
            | Some redirect -> Dream.redirect req redirect
            | None ->
              Dream.respond ~status:`Unauthorized
                (Printf.sprintf "Failed to sign-in")));
    ]
