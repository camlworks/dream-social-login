let github = Dream_oauth2.github
  ~client_id:(Sys.getenv "GH_CLIENT_ID")
  ~client_secret:(Sys.getenv "GH_CLIENT_SECRET")
  ~redirect_uri:(Sys.getenv "GH_REDIRECT_URI")
  ()

let stackoverflow = Dream_oauth2.stackoverflow
  ~client_id:(Sys.getenv "SO_CLIENT_ID")
  ~client_secret:(Sys.getenv "SO_CLIENT_SECRET")
  ~key:(Sys.getenv "SO_KEY")
  ~redirect_uri:(Sys.getenv "SO_REDIRECT_URI")
  ()

type message = {
  user : string;
  text : string;
}

let messages = ref [
  {user = "admin"; text = "This is a dummy message of the day!"};
]

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

% begin match Dream_oauth2.user_profile request with
% | None ->
    <p>Please sign in to chat!</p>
    <p><a href="<%s Dream_oauth2.signin_url github request %>">Sign in with GitHub</a></p>
    <p><a href="<%s Dream_oauth2.signin_url stackoverflow request %>">Sign in with StackOverflow</a></p>
    <hr>
% | Some profile ->
    <p>Signed in as <%s profile.Dream_oauth2.User_profile.display_name %> (<%s profile.provider %>).<p>
%   let signout_form = Dream_oauth2.signout_form request in
    <p><%s! signout_form %></p>
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

let () =
  Dream.run ~interface:"10.0.88.2" ~adjust_terminal:false
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router [

    Dream_oauth2.route github;
    Dream.scope "/so" [] [Dream_oauth2.route stackoverflow];

    Dream.get "/" (fun request ->
      Dream.html (render request));

    Dream.post "/" (fun request ->
      match Dream_oauth2.user_profile request with
      | None ->
        Dream.redirect request "/"
      | Some profile ->
        match%lwt Dream.form request with
        | `Ok ["text", text] ->
          messages :=
            {user = profile.Dream_oauth2.User_profile.display_name; text}::!messages;
          Dream.redirect request "/"
        | _ ->
          Dream.redirect request "/");
  ]
