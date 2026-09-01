# frozen_string_literal: true

require 'singleton'
require 'rest-client'

class TokenValidator::OauthTokenService
  include Singleton
  include TokenValidator::TokenCacheHelper

  # +issuer+ omitted means the primary issuer, so existing callers are unaffected.
  def access_token(issuer = nil)
    fetch_access_token(issuer)
  end

  def basic_http_header(issuer = nil)
    token = access_token(issuer)
    return { authorization: "Basic #{::Base64.strict_encode64("#{token[:token]}:")}" } unless token.nil?

    {}
  end

  def oauth_auth_header(issuer = nil)
    token = access_token(issuer)
    return { authorization: "Bearer #{token[:token]}" } unless token.nil?

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
