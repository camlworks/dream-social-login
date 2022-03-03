module User_profile = Oauth2.User_profile

type authenticate_result = Oauth2.authenticate_result
and provider_error = Oauth2.provider_error

let provider_error_to_string = Oauth2.provider_error_to_string

module Github = Github
module Twitch = Twitch
module Stackoverflow = Stackoverflow
