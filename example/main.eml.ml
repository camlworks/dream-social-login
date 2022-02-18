let client_id = Sys.getenv "OAUTH2_CLIENT_ID"
let client_secret = Sys.getenv "OAUTH2_CLIENT_SECRET"
let redirect_uri = Sys.getenv "OAUTH2_REDIRECT_URI"

type message = {
  user : string;
  text : string;
}

let messages = ref [{ user = "Unknown"; text = "HELLO" }]

let add_message ~user text = messages := { user; text } :: !messages

let render request =
  <html>
  <body>

% begin match Dream_oauth2.user_profile request with
% | None ->
    <p>Please <a href='/oauth2/signin'>sign in</a>!
% | Some profile ->
    <p>Hello, <%s profile.Dream_oauth2.User_profile.user %>!<p>
    <p><a href='/oauth2/signout'>Sign out</a></p>
    <form method="POST" action="/">
      <%s! Dream.csrf_tag request %>
      <textarea name="message"></textarea>
      <input type="submit" />
    </form>
% end;

  <ul>
%    !messages |> List.iter begin fun message ->
      <li><%s message.user %>: <%s message.text %></li>
%   end;
  </ul>

  </body>
  </html>

let () =
  Dream.run
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router
       [
         Dream_oauth2.route ~client_id ~client_secret ~redirect_uri ();
         Dream.get "/" (fun request ->
          Dream.html (render request));
         Dream.post "/" (fun request ->
             match Dream_oauth2.user_profile request with
             | None -> Dream.redirect request "/"
             | Some user -> (
               match%lwt Dream.form request with
               | `Ok [("message", message)] ->
                 add_message ~user:user.Dream_oauth2.User_profile.user message;
                 Dream.redirect request "/"
               | _ -> Dream.redirect request "/"));
       ]
