(* This example provides a small forum application where anyone with GitHub,
   Stackoverflow or Twitch account can post to. *)

type message = {
  user : string;
  text : string;
}

let messages = ref [
  {user = "admin"; text = "This is a dummy message of the day!"};
]

(* First we configure OAuth2 providers for GitHub, Stackoverflow and Twitch
   respectively. *)

let () = Dream.initialize_log ~level:`Debug ()

let github =
  Dream_oauth2.Github.make
    ~client_id:(Sys.getenv "GH_CLIENT_ID")
    ~client_secret:(Sys.getenv "GH_CLIENT_SECRET")
    ~redirect_uri:(Sys.getenv "GH_REDIRECT_URI")
    ()

let stackoverflow =
  Dream_oauth2.Stackoverflow.make
    ~client_id:(Sys.getenv "SO_CLIENT_ID")
    ~client_secret:(Sys.getenv "SO_CLIENT_SECRET")
    ~redirect_uri:(Sys.getenv "SO_REDIRECT_URI")
    ~key:(Sys.getenv "SO_KEY")
    ()

let twitch =
  Dream_oauth2.Twitch.make
    ~client_id:(Sys.getenv "TWITCH_CLIENT_ID")
    ~client_secret:(Sys.getenv "TWITCH_CLIENT_SECRET")
    ~redirect_uri:(Sys.getenv "TWITCH_REDIRECT_URI")
    ()

let google = Dream_oidc.google
  ~client_id:(Sys.getenv "GOOGLE_CLIENT_ID")
  ~client_secret:(Sys.getenv "GOOGLE_CLIENT_SECRET")
  ~redirect_uri:(Sys.getenv "GOOGLE_REDIRECT_URI")
  ()

let microsoft = Dream_oidc.microsoft
  ~client_id:(Sys.getenv "MS_CLIENT_ID")
  ~client_secret:(Sys.getenv "MS_CLIENT_SECRET")
  ~redirect_uri:(Sys.getenv "MS_REDIRECT_URI")
  ()

(* XXX: See https://github.com/aantron/hyper/issues/5 *)
(* let gitlab = Dream_oidc.make *)
(*   ~client_id:(Sys.getenv "GITLAB_CLIENT_ID") *)
(*   ~client_secret:(Sys.getenv "GITLAB_CLIENT_SECRET") *)
(*   ~redirect_uri:(Sys.getenv "GITLAB_REDIRECT_URI") *)
(*   "https://gitlab.com" *)

let twitch_oidc = Dream_oidc.twitch
  ~client_id:(Sys.getenv "TWITCH_CLIENT_ID")
  ~client_secret:(Sys.getenv "TWITCH_CLIENT_SECRET")
  ~redirect_uri:(Sys.getenv "TWITCH_OIDC_REDIRECT_URI")
  ()

(* Now provide functions to signin, signout and query current user (if any) from
   the request.

   In this example we store only the display name with provider (which user
   originated from) in the session. In the real application you'd probably want
   to persist [User_profile.t] information in the database and only store user
   identifier in the session. *)

let signin user request =
  let user =
    Option.value user.Dream_oidc.User_profile.name ~default:user.id ^
    " (" ^ user.provider ^ ")"
  in
  Dream.set_session_field request "user" user

let signout request =
  Dream.set_session_field request "user" ""

let user request =
  match Dream.session_field request "user" with
  | Some "" | None -> None
  | Some v -> Some v

(* Our small forum application has a single page only.

   Note how we use `authorize_url` functions to generate
   links to start the sign in flow with each of the OAuth2 providers we have
   configured. *)

let oidc_authorize_url oidc name request =
  match%lwt Dream_oidc.authorize_url oidc request with
  | Ok url ->
    Lwt.return @@
      <a href="<%s url %>">Sign in with <%s name %></a>
  | Error _ ->
    Lwt.return @@
      <span>"Sign in with <%s name %>" is not available</span>

let render request =
  let%lwt google_url = oidc_authorize_url google "Google" request in
  let%lwt microsoft_url = oidc_authorize_url microsoft "Microsoft" request in
  let%lwt twitch_oidc_url = oidc_authorize_url twitch_oidc "Twitch (OIDC)" request in
  Lwt.return @@
  <html>
  <head>
  <style>

  body, input {
    font-family: Helvetica, sans-serif;
    font-size: 24px;
  }

  </style>
  </head>
  <body>

% begin match user request with
% | None ->
    <p>Please sign in to chat!</p>
    <p><a href="<%s Dream_oauth2.Github.authorize_url github request %>">Sign in with GitHub</a></p>
    <p><a href="<%s Dream_oauth2.Stackoverflow.authorize_url stackoverflow request %>">Sign in with StackOverflow</a></p>
    <p><a href="<%s Dream_oauth2.Twitch.authorize_url twitch request %>">Sign in with Twitch</a></p>
    <p><%s! google_url %></p>
    <p><%s! microsoft_url %></p>
    <p><%s! twitch_oidc_url %></p>
    <hr>
% | Some user ->
    <p>Signed in as <%s user %>.<p>
    <form method="POST" action="/signout">
      <%s! Dream.csrf_tag request %>
      <input type="submit" value="Sign out" />
    </form>
    <hr>
    <form method="POST" action="/">
      <%s! Dream.csrf_tag request %>
      <input type="text" name="text" autofocus>
      <input type="submit" value="Send">
    </form>
% end;

% !messages |> List.iter begin fun message ->
    <p><b><%s message.user %></b>&nbsp;&nbsp;&nbsp;<%s message.text %></p>
% end;

  </body>
  </html>

(* Now we define [authenticate_handler] which creates a new oauth/oidc callback
   endpoint for the specified [path].

   The logic which handles the result of [authenticate request] function call is
   application specific.
   *)

let authenticate_handler path authenticate =
  Dream.get path (fun request ->
    match%lwt authenticate request with
    | `Ok user_profile ->
      let%lwt () = signin user_profile request in
      Dream.redirect request "/"
    | `Error message ->
      Dream.respond ~status:`Unauthorized message
    | `Provider_error (error, description) ->
      let message =
        Dream_oauth2.provider_error_to_string error ^
        (description
        |> Option.map (fun description -> ": " ^ description)
        |> Option.value ~default:"")
      in
      Dream.respond ~status:`Unauthorized message
    | `Expired ->
      Dream.redirect request "/"
  )

let () =
  let () =
    (* Configure OIDC providers at startup. *)
    Lwt_main.run @@
      Lwt_list.iter_p
        (fun oidc ->
          match%lwt Dream_oidc.configure oidc with
          | Ok () -> Lwt.return ()
          | Error err ->
            let provider_uri = Dream_oidc.provider_uri oidc in
            Printf.eprintf
              "error configuring OIDC client for %s: %s"
              provider_uri err;
            Lwt.return ()
        )
        [google; microsoft; twitch_oidc]
  in
  Dream.run ~tls:true
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router [

    authenticate_handler "/oauth2/callback/github" (
      Dream_oauth2.Github.authenticate github);
    authenticate_handler "/oauth2/callback/stackoverflow" (
      Dream_oauth2.Stackoverflow.authenticate stackoverflow);
    authenticate_handler "/oauth2/callback/twitch" (
      Dream_oauth2.Twitch.authenticate twitch);

    authenticate_handler "/oidc/callback/google" (
      Dream_oidc.authenticate google);
    authenticate_handler "/oidc/callback/twitch" (
      Dream_oidc.authenticate twitch_oidc);
    authenticate_handler "/oidc/callback/microsoft" (
      Dream_oidc.authenticate microsoft);

    Dream.get "/" (fun request ->
      let%lwt page = render request in
      Dream.html page);

    Dream.post "/" (fun request ->
      match user request with
      | None ->
        Dream.redirect request "/"
      | Some user ->
        match%lwt Dream.form request with
        | `Ok ["text", text] ->
          messages := {user = user; text}::!messages;
          Dream.redirect request "/"
        | _ ->
          Dream.redirect request "/");

    Dream.post "/signout" (fun request ->
      match%lwt Dream.form request with
      | `Ok _ ->
        let%lwt () = signout request in
        Dream.redirect request "/"
      | `Expired _ | `Wrong_session _ ->
        Dream.redirect request "/"
      | `Invalid_token _
      | `Missing_token _
      | `Many_tokens _
      | `Wrong_content_type ->
        Dream.respond ~status:`Unauthorized "Failed to sign-out"
    );
  ]
