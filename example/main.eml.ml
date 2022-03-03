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

let github = {
  Dream_oauth2.Github.
  client_id = Sys.getenv "GH_CLIENT_ID";
  client_secret = Sys.getenv "GH_CLIENT_SECRET";
  redirect_uri = Sys.getenv "GH_REDIRECT_URI";
}

let stackoverflow = {
  Dream_oauth2.Stackoverflow.
  client_id = Sys.getenv "SO_CLIENT_ID";
  client_secret = Sys.getenv "SO_CLIENT_SECRET";
  key = Sys.getenv "SO_KEY";
  redirect_uri = Sys.getenv "SO_REDIRECT_URI";
}

let twitch = {
  Dream_oauth2.Twitch.
  client_id = Sys.getenv "TWITCH_CLIENT_ID";
  client_secret = Sys.getenv "TWITCH_CLIENT_SECRET";
  redirect_uri = Sys.getenv "TWITCH_REDIRECT_URI";
}

(* Now provide functions to signin, signout and query current user (if any) from
   the request.

   In this example we store only the display name with provider (which user
   originated from) in the session. In the real application you'd probably want
   to persist [User_profile.t] information in the database and only store user
   identifier in the session. *)

let signin user_profile request =
  let user =
    user_profile.Dream_oauth2.User_profile.display_name ^
    " (" ^ user_profile.provider ^ ")"
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

let render request =
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

let () = Dream.initialize_log ~level:`Debug ()

(* Now [handle_authenticate_result] is the piece of logic we have to handle the
   final result of the signin flow. *)

let handle_authenticate_result request result =
  match result with
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

let () =
  Dream.run ~tls:true
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router [

    (* Below we install OAuth2 callback handlers which all call into
       [Dream_oauth2.authenticate]. *)

    Dream.get "/oauth2/callback/github" (fun request ->
      let%lwt authenticate_result =
        Dream_oauth2.Github.authenticate
          github request
      in
      handle_authenticate_result request authenticate_result
    );
    Dream.get "/oauth2/callback/stackoverflow" (fun request ->
      let%lwt authenticate_result =
        Dream_oauth2.Stackoverflow.authenticate
          stackoverflow request
      in
      handle_authenticate_result request authenticate_result
    );
    Dream.get "/oauth2/callback/twitch" (fun request ->
      let%lwt authenticate_result =
        Dream_oauth2.Twitch.authenticate
          twitch request
      in
      handle_authenticate_result request authenticate_result
    );

    Dream.get "/" (fun request ->
      Dream.html (render request));

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
