module User_profile = Oauth2.User_profile

type authenticate_result = Oauth2.authenticate_result

type access_token =
  Dream.request -> code:string -> (string, string) result Lwt.t

type user_profile =
  Dream.request -> access_token:string -> (User_profile.t, string) result Lwt.t

let authenticate = Oauth2.authenticate

module Github = Github
module Twitch = Twitch
module Stackoverflow = Stackoverflow
