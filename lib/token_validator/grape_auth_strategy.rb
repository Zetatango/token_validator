# frozen_string_literal: true

require 'rack'
require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'

# env key to store the token info
REQUEST_TOKEN_INFO = "token.info"

class TokenValidator::GrapeAuthStrategy < Rack::Auth::AbstractHandler
  def call(env)
    auth = TokenValidator::GrapeAuthStrategy::Request.new env

    return unauthorized unless auth.provided?
    return bad_request unless auth.bearer?

    endpoint_scopes = env['api.endpoint'].route_setting(:scopes) || []
    service = TokenValidator::TokenService.new(auth.params, endpoint_scopes)

    begin
      env[REQUEST_TOKEN_INFO] = service.decoded_jwt.except("iss", "kid", "aud", "iat", "exp", "jti", "scopes").to_hash
    rescue StandardError
      env[REQUEST_TOKEN_INFO] = "Unable to read"
    end

    return @app.call(env) if valid? service

    unauthorized
  end

  private

  def challenge
    "Bearer realm=\"#{realm}\""
  end

  def valid?(service)
    return false unless service.valid_access_token?

    @authenticator.call service.decoded_jwt
  end

  class Request < Rack::Auth::AbstractRequest
    def bearer?
      scheme == "bearer"
    end
  end
end
