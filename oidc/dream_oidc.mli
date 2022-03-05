module User_profile = Dream_oauth2.User_profile

type oidc
(** OIDC client. *)

val make :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  string ->
  oidc
(** Create an OIDC client which uses OpenID Connect Discovery mechanism to
    configure itself.

    Note that this function doesn't do any configuration itsef, you need to
    call [configure] on its result to perform an actual configuration which
    involves making HTTP requests to an OIDC provider. Before [configure]
    function call is made the client is in unusable state.

    Parameters [client_id], [client_secret] should be obtained from OIDC
    provider by registering a client (usually called "application") with it.

    Parameter [redirect_uri] is the location the Dream application is accessible
    by the OIDC provider. On this location there should be a GET handler
    installed which calls [authenticate] function to perform a final part of the
    authentication flow.

    Optional parameter [scope] specifies what access privileges are requested
    from a user. Note that `"openid"` scope is always requested (as specified by
    OIDC protocol). Other possible values are `"profile"`, `"email"` (see the
    list at https://openid.net/specs/openid-connect-basic-1_0.html#Scopes).

    Optional parameter [user_claims] specifies what claims should be fetched
    from userinfo endpoint (see the list of standard OIDC claims here
    https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).

 *)

val configure : oidc -> (unit, string) Lwt_result.t
(** Configure an OIDC client using OpenID Connect Discovery mechanism.

    See https://openid.net/specs/openid-connect-discovery-1_0.html for more
    information.
  *)

val provider_uri : oidc -> string
(** Get OIDC client provider URI. *)

val google :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  oidc
(**

  Pre-configured Google OIDC client.

  See https://console.cloud.google.com/apis/credentials for acquiring
  [client_id], [client_secret] values.
  *)

val microsoft :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  oidc
(**

  Pre-configured Microsoft OIDC client.

  See "Azure Active Directory" at https://portal.azure.com/ for acquiring
  [client_id], [client_secret] values.
  *)

val twitch :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  oidc
(**

  Pre-configured Twitch OIDC client.

  See https://dev.twitch.tv/docs/authentication/#registration for acquiring
  [client_id], [client_secret] values.
  *)

val authorize_url : oidc -> Dream.request -> (string, string) Lwt_result.t
(** Produce an URL to start signin flow with GitHub. *)

val authenticate :
  oidc -> Dream.request -> Dream_oauth2.authenticate_result Lwt.t
(** Get the result of authentication. This should be called inside the OAuth2
    callback handler.*)
