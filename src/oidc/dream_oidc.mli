module User_profile = Dream_oauth.User_profile

type client
(** OIDC client. *)

val make :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  string ->
    client
(** Create an OIDC client which uses OpenID Connect Discovery mechanism to
    configure itself.

    Note that this function doesn't do any configuration itsef, you need to
    call [configure] on its result to perform an actual configuration, which
    involves making HTTP requests to an OIDC provider. Before the [configure]
    function call is made, the client is in unusable state.

    Parameters [client_id], [client_secret] should be obtained from the OIDC
    provider by registering a client (usually called "application") with it.

    Parameter [redirect_uri] is the location the Dream application is accessible
    by the OIDC provider. On this location there should be a GET handler
    installed which calls the [authenticate] function to perform a final part of
    the authentication flow.

    Optional parameter [scope] specifies what access privileges are requested
    from a user. Note that ["openid"] scope is always requested (as specified by
    OIDC protocol). Other possible values are ["profile"], ["email"]. See the
    list at https://openid.net/specs/openid-connect-basic-1_0.html#Scopes.

    Optional parameter [user_claims] specifies what claims should be fetched
    from userinfo endpoint. See the list of standard OIDC claims here
    https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims. *)

val configure : client -> (unit, string) Lwt_result.t
(** Configure an OIDC client using OpenID Connect Discovery mechanism.

    See https://openid.net/specs/openid-connect-discovery-1_0.html for more
    information. *)

val provider_uri : client -> string
(** Get OIDC client provider URI. *)

val authorize_url : client -> Dream.request -> (string, string) result Lwt.t
(** Produce a URL to start the login flow with an OIDC provider. *)

type authenticate_result = Dream_oauth.authenticate_result
and provider_error = Dream_oauth.provider_error

val provider_error_to_string : provider_error -> string
val provider_error_of_string : string -> provider_error option

val authenticate :
  client -> Dream.request -> Dream_oauth.authenticate_result Lwt.t
(** Get the result of authentication. This should be called inside the OAuth2
    callback handler.*)

val google :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
    client
(** Google OIDC client.

    See https://console.cloud.google.com/apis/credentials for acquiring
    [client_id], [client_secret] values. *)

val microsoft :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
    client
(** Microsoft OIDC client.

    See "Azure Active Directory" at https://portal.azure.com for acquiring
    [client_id], [client_secret] values. *)

val twitch :
  ?user_claims:string list ->
  ?scope:string list ->
  client_id:string ->
  client_secret:string ->
  redirect_uri:string ->
  unit ->
    client
(** Twitch OIDC client.

    See https://dev.twitch.tv/docs/authentication/#registration for acquiring
    [client_id], [client_secret] values. *)
