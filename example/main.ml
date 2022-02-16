let client_id = Sys.getenv "OAUTH2_CLIENT_ID"
let client_secret = Sys.getenv "OAUTH2_CLIENT_SECRET"
let redirect_uri = Sys.getenv "OAUTH2_REDIRECT_URI"

module Messages = struct
  type message = {
    user : string;
    message : string;
  }

  let messages = ref [{ user = "Unknown"; message = "HELLO" }]

  let render () =
    let items =
      !messages
      |> ListLabels.map ~f:(fun msg ->
             Printf.sprintf "<li>%s: %s</li>" msg.user msg.message)
      |> String.concat "\n"
    in
    Printf.sprintf "<ul>%s<uk>" items

  let add ~user message = messages := { user; message } :: !messages
end

let () =
  let () =
    match Sys.getenv_opt "DEBUG" with
    | None | Some ("no" | "NO" | "0") -> ()
    | Some _ -> Dream.initialize_log ~level:`Debug ()
  in
  Dream.run ~adjust_terminal:false ?interface:(Sys.getenv_opt "INTERFACE")
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router
       [
         Dream_oauth2.route ~client_id ~client_secret ~redirect_uri ();
         Dream.get "/" (fun req ->
             match Dream_oauth2.user_profile req with
             | None ->
               Dream.respond
                 ("<p>Please <a href='/oauth2/signin'>sign in</a>!"
                 ^ Messages.render ())
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
                   user.Dream_oauth2.User_profile.user (Dream.csrf_tag req)
               in
               Dream.respond (header ^ Messages.render ()));
         Dream.post "/" (fun req ->
             match Dream_oauth2.user_profile req with
             | None -> Dream.redirect req "/"
             | Some user -> (
               match%lwt Dream.form req with
               | `Ok [("message", message)] ->
                 Messages.add ~user:user.Dream_oauth2.User_profile.user message;
                 Dream.redirect req "/"
               | _ -> Dream.redirect req "/"));
       ]
