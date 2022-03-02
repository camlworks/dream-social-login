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

include Cookie_with_expiration (struct
  let max_age = 60.0 *. 60.0 *. 24.0 *. 7.0 (* a week *)

  let cookie_name = "dream_oauth2.auth"

  type value = Oauth2.User_profile.t

  let value_to_yojson { Oauth2.User_profile.id; display_name; email; provider }
      =
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
        Ok
          { Oauth2.User_profile.id; display_name; email = Some email; provider }
      | `Null ->
        Ok { Oauth2.User_profile.id; display_name; email = None; provider }
      | _ -> Error "invalid User_profile.t")
    | _ -> Error "invalid User_profile.t"
end)
