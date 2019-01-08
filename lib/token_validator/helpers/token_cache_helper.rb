# frozen_string_literal: true

require 'rails'
require 'rest-client'

module TokenValidator::TokenCacheHelper
  protected

  CACHE_NAMESPACE = 'oauth_token_service'
  ISSUER_JWKS_KEY = 'issuer-jwks'
  ACCESS_TOKEN = 'access-token'

  def fetch_access_token
    @access_token = Rails.cache&.read(ACCESS_TOKEN, namespace: namespace)
    @access_token = request_access_token if @access_token.nil?

    @access_token
  end

  def fetch_signing_key
    Rails.cache.nil? ? download_signing_key : Rails.cache.fetch(ISSUER_JWKS_KEY, namespace: namespace) { download_signing_key }
  end

  def clear_cache_if_available
    Rails.cache&.clear(namespace: namespace)
  end

  def download_signing_key
    jwks = JSON.parse(
      RestClient.get(oauth_path('discovery/keys'))
    ).with_indifferent_access
    JSON::JWK::Set.new jwks[:keys]
  rescue Errno::ECONNREFUSED, RestClient::Exception
    nil
  end

  def request_access_token
    response = RestClient.post(oauth_path(:token), grant_type: :client_credentials,
                                                   client_id: TokenValidator::ValidatorConfig.config[:client_id],
                                                   client_secret: TokenValidator::ValidatorConfig.config[:client_secret],
                                                   scope: TokenValidator::ValidatorConfig.config[:requested_scope])
    access_token = {
      token: JSON.parse(response)['access_token'],
      expires: Time.now.to_i + JSON.parse(response)['expires_in'],
      expires_in: JSON.parse(response)['expires_in']
    }

    unless access_token.nil?
      Rails.cache&.write(
        ACCESS_TOKEN,
        access_token,
        namespace: namespace,
        expires_in: access_token[:expires_in] - 3.minutes
      )
    end

    access_token
  rescue Errno::ECONNREFUSED, RestClient::Exception
    nil
  end

  def oauth_path(action)
    "#{TokenValidator::ValidatorConfig.config[:issuer_url]}/oauth/#{action}"
  end

  private

  def namespace
    # We do not use a cache for unit tests
    # :nocov:
    "#{Digest::SHA256.hexdigest(Rails.application.class.parent_name.downcase)}_#{CACHE_NAMESPACE}"
    # :nocov:
  end
end
