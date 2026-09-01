# frozen_string_literal: true

require 'singleton'
require 'rest-client'

class TokenValidator::OauthTokenService
  include Singleton
  include TokenValidator::TokenCacheHelper

  def access_token
    fetch_access_token
  end

  def basic_http_header
    return { authorization: "Basic #{::Base64.strict_encode64("#{access_token[:token]}:")}" } unless access_token.nil?

    {}
  end

  def oauth_auth_header
    return { authorization: "Bearer #{access_token[:token]}" } unless access_token.nil?

    {}
  end

  # +issuer+ omitted means the primary issuer, so existing callers are unaffected.
  def signing_key(issuer = nil)
    fetch_signing_key(issuer)
  end

  def get_token_info(token)
    return nil unless token

    response = RestClient.get(oauth_path('token/info'), authorization: "Bearer #{token}")

    JSON.parse(response)
  rescue Errno::ECONNREFUSED, RestClient::Exception
    nil
  end

  def clear
    clear_cache_if_available
    @access_token = nil
  end
end
