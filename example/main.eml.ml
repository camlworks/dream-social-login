let client_id = Sys.getenv "OAUTH2_CLIENT_ID"
let client_secret = Sys.getenv "OAUTH2_CLIENT_SECRET"
let redirect_uri = Sys.getenv "OAUTH2_REDIRECT_URI"

type message = {
  user : string;
  message : string;
}

let messages = ref [{ user = "Unknown"; message = "HELLO" }]

let render_messages () =
  let items =
    !messages
    |> ListLabels.map ~f:(fun msg ->
           Printf.sprintf "<li>%s: %s</li>" msg.user msg.message)
    |> String.concat "\n"
  in
  Printf.sprintf "<ul>%s</ul>" items

let add_message ~user message = messages := { user; message } :: !messages

let () =
  Dream.run
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router
       [
         Dream_oauth2.route ~client_id ~client_secret ~redirect_uri ();
         Dream.get "/" (fun request ->
             match Dream_oauth2.user_profile request with
             | None ->
               Dream.respond
                 ("<p>Please <a href='/oauth2/signin'>sign in</a>!"
                 ^ render_messages ())
             | Some user ->
               let header =
                 Printf.sprintf
                   {|
                      <p>Hello, %s!<p>
                      <p><a href='/oauth2/signout'>Sign out</a></p>
                      <form method="POST" action="/">
                        %s
                        <textarea name="message"></textarea>
                        <input type="submit" />
                      </form>
                    |}
                   user.Dream_oauth2.User_profile.user (Dream.csrf_tag request)
               in
               Dream.respond (header ^ render_messages ()));
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
