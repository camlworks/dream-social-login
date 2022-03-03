module User_profile = Oauth2.User_profile

type authenticate_result = Oauth2.authenticate_result
type authenticate = Dream.request -> authenticate_result Lwt.t

module Github = Github
module Twitch = Twitch
module Stackoverflow = Stackoverflow
