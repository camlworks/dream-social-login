module User_profile = Dream_oauth2.User_profile

type config
(** Configured OIDC client. *)

val configure :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  string ->
  config
(** Configure an OIDC client using OpenID Connect Discovery mechanism.

    See https://openid.net/specs/openid-connect-discovery-1_0.html

    [configure ~client_id ~client_secret ~redirect_uri provider_uri] makes a
    request to [provider_uri]/.well-known/openid-configuration URL to get JSON
    encoded information about an OIDC provider endpoints and supported features.

    Parameters [client_id], [client_secret] should be obtained from OIDC
    provider by registering a client (usually called "application") with it.

    Parameter [redirect_uri] is the location the Dream application is accessible
    by the OIDC provider. On this location there should be a GET handler
    installed which calls [authenticate] function to perform a final part of the
    authentication flow.

    Optional parameter [scope] specifies what access privileges are requested
    from a user. Note that `"openid"` scope is always requested (as specified by
    OIDC protocol). Other possible values are `"profile"`, `"email"` (see the
    lsit at https://openid.net/specs/openid-connect-basic-1_0.html#Scopes).

 *)

val google :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
  config
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
  config
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
  config
(**

  Pre-configured Twitch OIDC client.

  See https://dev.twitch.tv/docs/authentication/#registration for acquiring
  [client_id], [client_secret] values.
  *)

val authorize_url : config -> Dream.request -> string
(** Produce an URL to start signin flow with GitHub. *)

val authenticate :
  config -> Dream.request -> Dream_oauth2.authenticate_result Lwt.t
(** Get the result of authentication. This should be called inside the OAuth2
    callback handler.*)
