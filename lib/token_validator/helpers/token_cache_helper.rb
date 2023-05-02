# frozen_string_literal: true

require 'rails'
require 'rest-client'

module TokenValidator::TokenCacheHelper
  protected

  CACHE_NAMESPACE = 'oauth_token_service'
  ISSUER_JWKS_KEY = 'issuer-jwks'
  OPENID_CONFIGURATION_KEY = 'openid-configuration'
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
      RestClient.get(openid_configuration[:jwks_uri])
    ).with_indifferent_access
    JSON::JWK::Set.new jwks[:keys]
  rescue Errno::ECONNREFUSED, RestClient::Exception => e
    TokenValidator::ValidatorConfig.logger.error "Unable to access jwks_uri endpoint: #{e.message}"
    nil
  end

  def request_access_token
    response = RestClient.post(openid_configuration[:token_endpoint], grant_type: :client_credentials,
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
  rescue Errno::ECONNREFUSED, RestClient::Exception => e
    puts TokenValidator::ValidatorConfig.config
    TokenValidator::ValidatorConfig.logger.error "Unable to access token endpoint #{openid_configuration[:token_endpoint]}: #{e.message}"
    nil
  end

  def openid_configuration
    Rails.cache.nil? ? download_openid_configuration : Rails.cache.fetch(OPENID_CONFIGURATION_KEY, namespace: namespace) { download_openid_configuration }
  end

  private

  def download_openid_configuration
    url = "#{TokenValidator::ValidatorConfig.config[:issuer_url]}.well-known/openid-configuration"
    response = RestClient.get(url)
    JSON.parse(response.body, symbolize_names: true)
  rescue Errno::ECONNREFUSED, RestClient::Exception => e
    TokenValidator::ValidatorConfig.logger.error "Unable to access configuration endpoint #{url}: #{e.message}"
    raise e
  end

  def namespace
    # We do not use a cache for unit tests
    # :nocov:
    "#{Digest::SHA256.hexdigest(Rails.application.class.module_parent_name.downcase)}_#{CACHE_NAMESPACE}"
    # :nocov:
  end
end
