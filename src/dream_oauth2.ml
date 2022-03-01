module User_profile = struct
  type t = {
    id : string;
    display_name : string;
    email : string option;
    provider : string;
  }
  (** Information about an authenticated user.

      The fields choosen to be commonly available from most identity providers.
    *)
end

module type OAUTH2_PROVIDER = sig
  type config

  val authorize_url : state:string -> config -> string
  val access_token : code:string -> config -> (string, string) result Lwt.t

  val user_profile :
    access_token:string -> config -> (User_profile.t, string) result Lwt.t
end

module type OAUTH2 = sig
  module Provider : OAUTH2_PROVIDER

  val config : Provider.config
end

type oauth2 = (module OAUTH2)

(* XXX: should be added by Hyper? *)
let user_agent = "hyper/1.0.0"
let log = Dream.sub_log "dream-oauth2"

module Helper = struct
  let url ?(params = []) base =
    match params with
    | [] -> base
    | params -> Printf.sprintf "%s?%s" base (Hyper.to_form_urlencoded params)

  let handle_resp resp =
    match Dream_pure.Message.status resp with
    | #Dream_pure.Status.successful -> (
      match%lwt Dream_encoding.with_decoded_body resp with
      | Ok resp -> Lwt.return_ok resp
      | Error err ->
        log.debug (fun log -> log "error decoding response body: %s" err);
        Lwt.return_error "error decoding response body")
    | status ->
      let status = Dream_pure.Status.status_to_string status in
      let%lwt body =
        match%lwt Dream_encoding.with_decoded_body resp with
        | Ok resp -> Dream_pure.Message.body resp
        | Error _ -> Lwt.return "<error>"
      in
      log.debug (fun log ->
          log "POST request failed status=%s body=%s" status body);
      Lwt.return_error ("response status code: " ^ status)

  let post ?params ?(headers = []) ?body url_base =
    let body, headers =
      match body with
      | None -> (None, headers)
      | Some (`Form params) ->
        let body = Dream_pure.Formats.to_form_urlencoded params in
        ( Some (Dream_pure.Stream.string body),
          ("Content-Type", "application/x-www-form-urlencoded")
          :: ("Content-Length", Int.to_string (String.length body))
          :: headers )
    in
    Lwt.bind
      (Hyper.run
      @@ Hyper.request (url ?params url_base) ~method_:`POST ?body
           ~headers:(("User-Agent", user_agent) :: headers))
      handle_resp

  let get ?params ?(headers = []) url_base =
    Lwt.bind
      (Hyper.run
      @@ Hyper.request (url ?params url_base) ~method_:`GET
           ~headers:(("User-Agent", user_agent) :: headers))
      handle_resp
end

module Github = struct
  type config = {
    client_id : string;
    client_secret : string;
    redirect_uri : string;
    scope : string list;
  }

  let name = "github"

  (** [authorize_url] is used to produce a URL to redirect browser to for
      authentication flow. *)
  let authorize_url ~state config =
    Helper.url "https://github.com/login/oauth/authorize"
      ~params:
        [
          ("client_id", config.client_id);
          ("redirect_uri", config.redirect_uri);
          ("state", state);
          (* XXX: empty scope? *)
          ("scope", StringLabels.concat ~sep:" " config.scope);
        ]

  (** [access_token] performs a request to acquire an access_token. *)
  let access_token ~code config =
    log.debug (fun log -> log "getting access_token");
    let%lwt resp =
      Helper.post "https://github.com:443/login/oauth/access_token"
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
    let exception User_profile_error of string in
    try%lwt
      let%lwt resp =
        Helper.get "https://api.github.com:443/user"
          ~headers:
            [
              ("Authorization", "token " ^ access_token);
              ("Host", "api.github.com");
              ("Accept", "application/json");
            ]
      in
      match resp with
      | Ok resp ->
        let%lwt body = Dream_pure.Message.body resp in
        let json =
          try Yojson.Basic.from_string body
          with Yojson.Json_error _ ->
            log.debug (fun log -> log "user_profile response body=%s" body);
            raise (User_profile_error "error parsing JSON response")
        in
        let json_string_field key json =
          Yojson.Basic.Util.(
            try to_string (member key json)
            with Type_error _ ->
              log.debug (fun log -> log "user_profile response body=%s" body);
              raise
                (User_profile_error
                   (Printf.sprintf
                      "error decoding JSON: missing or invalid `%s` field" key)))
        in
        let login = json_string_field "login" json in
        let email = json_string_field "email" json in
        Lwt.return_ok
          {
            User_profile.id = login;
            display_name = login;
            email = Some email;
            provider = name;
          }
      | Error err -> raise (User_profile_error err)
    with User_profile_error reason -> Lwt.return_error reason
end

let github ?(scope = []) ~client_id ~client_secret ~redirect_uri () =
  (module struct
    module Provider = Github

    let config = { Github.client_id; client_secret; redirect_uri; scope }
  end : OAUTH2)

module Stack_overflow = struct
  type config = {
    client_id : string;
    client_secret : string;
    key : string;
    redirect_uri : string;
    scope : string list;
  }

  let name = "stackoverflow"

  let authorize_url ~state config =
    let params =
      Hyper.to_form_urlencoded
        [
          ("client_id", config.client_id);
          ("redirect_uri", config.redirect_uri);
          ("state", state);
          (* XXX: empty scope? *)
          ("scope", StringLabels.concat ~sep:" " config.scope);
        ]
    in
    "https://stackoverflow.com/oauth?" ^ params

  let access_token ~code config =
    log.debug (fun log -> log "getting access_token");
    let%lwt resp =
      Helper.post "https://stackoverflow.com:443/oauth/access_token"
        ~body:
          (`Form
            [
              ("client_id", config.client_id);
              ("client_secret", config.client_secret);
              ("code", code);
              ("redirect_uri", config.redirect_uri);
            ])
        ~headers:[("Host", "stackoverflow.com"); ("Accept", "*/*")]
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

  let user_profile ~access_token config =
    log.debug (fun log -> log "getting user_profile");
    let exception User_profile_error of string in
    try%lwt
      let%lwt resp =
        Helper.get "https://api.stackexchange.com:443/2.3/me"
          ~params:
            [
              ("access_token", access_token);
              ("key", config.key);
              ("site", "stackoverflow");
            ]
          ~headers:
            [
              ("Authorization", "token " ^ access_token);
              ("Host", "api.stackexchange.com");
              ("Accept", "application/json");
              ("User-Agent", user_agent);
            ]
      in
      match resp with
      | Ok resp ->
        let%lwt body = Dream_pure.Message.body resp in
        let json =
          try Yojson.Basic.from_string body
          with Yojson.Json_error _ ->
            log.debug (fun log -> log "user_profile response body=%s" body);
            raise (User_profile_error "error parsing JSON response")
        in
        let profile =
          try
            Yojson.Basic.Util.(
              let user = json |> member "items" |> index 0 in
              {
                User_profile.id =
                  user |> member "user_id" |> to_int |> Int.to_string;
                display_name = user |> member "display_name" |> to_string;
                email = None;
                provider = name;
              })
          with Yojson.Basic.Util.Type_error _ ->
            log.debug (fun log -> log "user_profile response body=%s" body);
            raise
              (User_profile_error
                 (Printf.sprintf "error parsing user_profile response"))
        in
        Lwt.return_ok profile
      | Error err -> raise (User_profile_error err)
    with User_profile_error reason -> Lwt.return_error reason
end

let stackoverflow ?(scope = []) ~client_id ~client_secret ~redirect_uri ~key ()
    =
  (module struct
    module Provider = Stack_overflow

    let config =
      { Stack_overflow.client_id; client_secret; redirect_uri; key; scope }
  end : OAUTH2)

module type COOKIE_SPEC = sig
  val cookie_name : string
  val max_age : float

  type value

  val value_to_yojson : value -> Yojson.Basic.t
  val value_of_yojson : Yojson.Basic.t -> (value, string) result
end

module Cookie_with_expiration (Spec : COOKIE_SPEC) : sig
  type value

  val set : Dream.response -> Dream.request -> value -> unit
  val get : Dream.request -> value option
  val drop : Dream.response -> Dream.request -> unit
end
with type value := Spec.value = struct
  type 'a packed = {
    expires : float;
    value : 'a;
  }

  let packed_to_yojson { expires; value } =
    `Assoc [("expires", `Float expires); ("value", Spec.value_to_yojson value)]

  let packed_of_yojson (json : Yojson.Basic.t) =
    let ( >>= ) = Result.bind in
    match json with
    | `Assoc [("expires", expires); ("value", value)] ->
      (match expires with
      | `Int v -> Ok (Int.to_float v)
      | `Float v -> Ok v
      | _ -> Error "invalid Packed.t")
      >>= fun expires ->
      Spec.value_of_yojson value >>= fun value -> Ok { expires; value }
    | _ -> Error "invalid Packed.t"

  let set res req value =
    let now = Unix.gettimeofday () in
    let expires = now +. Spec.max_age in
    Dream.set_cookie ~http_only:true
      ~same_site:(Some `Lax)
      ~expires ~encrypt:true res req Spec.cookie_name
      (Yojson.Basic.to_string (packed_to_yojson { expires; value }))

  let get req =
    let now = Unix.gettimeofday () in
    Option.bind (Dream.cookie ~decrypt:true req Spec.cookie_name)
    @@ fun value ->
    match Yojson.Basic.from_string value with
    | json -> (
      match packed_of_yojson json with
      | Ok { expires; value } -> if expires > now then Some value else None
      | Error _ -> None)
    | exception Yojson.Json_error _ -> None

  let drop res req = Dream.drop_cookie ~http_only:true res req Spec.cookie_name
end

module Auth_cookie = Cookie_with_expiration (struct
  let max_age = 60.0 *. 60.0 *. 24.0 *. 7.0 (* a week *)

  let cookie_name = "dream_oauth2.auth"

  type value = User_profile.t

  let value_to_yojson { User_profile.id; display_name; email; provider } =
    `Assoc
      [
        ("id", `String id);
        ("display_name", `String display_name);
        ( "email",
          email
          |> Option.map (fun v -> `String v)
          |> Option.value ~default:`Null );
        ("provider", `String provider);
      ]

  let value_of_yojson json =
    match json with
    | `Assoc
        [
          ("id", `String id);
          ("display_name", `String display_name);
          ("email", email);
          ("provider", `String provider);
        ] -> (
      match email with
      | `String email ->
        Ok { User_profile.id; display_name; email = Some email; provider }
      | `Null -> Ok { User_profile.id; display_name; email = None; provider }
      | _ -> Error "invalid User_profile.t")
    | _ -> Error "invalid User_profile.t"
end)

let user_profile = Auth_cookie.get
let signout = Auth_cookie.drop

let signin_url ?(valid_for = 60. *. 60. *. 1. (* 1 hour *)) oauth2 req =
  let module Oauth2 = (val oauth2 : OAUTH2) in
  let state = Dream.csrf_token ~valid_for req in
  Oauth2.Provider.authorize_url Oauth2.config ~state

let signout_form ?(signout_url = "/oauth2/signout") req =
  Printf.sprintf
    {|<form method="POST" action="%s">
        %s
        <input type="submit" value="Sign out" />
      </form>|}
    signout_url (Dream.csrf_tag req)

let route ?(redirect_on_signin = "/") ?(redirect_on_signout = "/")
    ?(redirect_on_signin_expired = "/") ?(redirect_on_signout_expired = "/")
    oauth2 =
  let module Oauth2 = (val oauth2 : OAUTH2) in
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
            let%lwt () =
              let state =
                match Dream.query req "state" with
                | Some v -> v
                | None -> error "no `state` parameter in callback request"
              in
              match%lwt Dream.verify_csrf_token req state with
              | `Ok -> Lwt.return ()
              | `Expired _ | `Wrong_session ->
                error ~redirect:redirect_on_signin_expired
                  "expired `state` parameter"
              | `Invalid -> error "invalid `state` parameter"
            in
            let code =
              match Dream.query req "code" with
              | Some v -> v
              | None -> error "no `code` parameter in callback request"
            in
            let%lwt access_token =
              match%lwt Oauth2.Provider.access_token Oauth2.config ~code with
              | Ok access_token -> Lwt.return access_token
              | Error err -> error ("error getting access_token: " ^ err)
            in
            let%lwt user_profile =
              match%lwt
                Oauth2.Provider.user_profile ~access_token Oauth2.config
              with
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
                "Failed to sign-in with GitHub"));
    ]
