let client_id = Sys.getenv "OAUTH2_CLIENT_ID"
let client_secret = Sys.getenv "OAUTH2_CLIENT_SECRET"
let redirect_uri = Sys.getenv "OAUTH2_REDIRECT_URI"

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
    <p><a href="/oauth2/signin">Sign in with GitHub</a></p>
    <hr>
% | Some profile ->
    <p>Signed in as <%s profile.Dream_oauth2.User_profile.user %>.<p>
    <p><a href="/oauth2/signout">Sign out</a></p>
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

let () =
  Dream.run
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router [

    Dream_oauth2.route ~client_id ~client_secret ~redirect_uri ();

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
            {user = profile.Dream_oauth2.User_profile.user; text}::!messages;
          Dream.redirect request "/"
        | _ ->
          Dream.redirect request "/");
  ]
