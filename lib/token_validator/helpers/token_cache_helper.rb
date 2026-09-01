# frozen_string_literal: true

require 'rails'
require 'rest-client'

module TokenValidator::TokenCacheHelper
  protected

  CACHE_NAMESPACE = 'oauth_token_service'
  ISSUER_JWKS_KEY = 'issuer-jwks'
  ACCESS_TOKEN = 'access-token'

  def fetch_access_token
    @access_token = Rails.cache&.read(ACCESS_TOKEN, namespace:)
    @access_token = request_access_token if @access_token.nil?

    @access_token
  end

  # The signing keys for +issuer+, or for the primary issuer when none is given.
  #
  # Keys are held per issuer, and that isolation is the point of this method rather than an
  # optimisation. With one shared slot, keys downloaded for one issuer could be handed back to
  # verify a token claiming a different one -- so a caller must never be able to reach issuer A's
  # keys by asking for issuer B.
  def fetch_signing_key(issuer = nil)
    entry = signing_key_issuer_entry(issuer)

    # Not an issuer this library trusts. Returning nil rather than falling back to the primary
    # issuer's keys is deliberate: a fallback here is exactly the cross-issuer confusion the
    # per-issuer cache exists to prevent.
    return nil if entry.nil?

    return download_signing_key(entry[:jwks_url]) if Rails.cache.nil?

    Rails.cache.fetch(jwks_cache_key(entry[:issuer_url]), namespace:) { download_signing_key(entry[:jwks_url]) }
  end

  def clear_cache_if_available
    Rails.cache&.clear(namespace:)
  end

  # Fetches from the address the issuer entry carries, rather than building one. The primary
  # entry's +jwks_url+ is synthesised to be exactly what +oauth_path('discovery/keys')+ used to
  # produce -- double slash included -- so the primary issuer keeps resolving where it always has.
  def download_signing_key(jwks_url)
    jwks = JSON.parse(
      RestClient.get(jwks_url)
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
        namespace:,
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

  # An omitted issuer means the primary one, which is what every caller wanted before this library
  # knew about more than one.
  #
  # +nil+ and not +blank?+, deliberately. An empty or whitespace issuer is a *named* issuer that
  # happens to be blank -- typically a token whose +iss+ claim is empty or missing -- and
  # ValidatorConfig rejects exactly that. Treating blank as absent here would route around that
  # guard and hand back the primary issuer's keys, which is the cross-issuer confusion this
  # per-issuer lookup exists to prevent.
  def signing_key_issuer_entry(issuer)
    issuer = TokenValidator::ValidatorConfig.config[:issuer_url] if issuer.nil?

    TokenValidator::ValidatorConfig.issuer_config_for(issuer)
  end

  # Digested because an issuer URL is not safe to paste into a cache key, and because it keeps the
  # key a fixed length whatever the issuer. Any per-issuer key works; a shared one does not.
  def jwks_cache_key(issuer_url)
    "#{ISSUER_JWKS_KEY}-#{Digest::SHA256.hexdigest(issuer_url)}"
  end

  def namespace
    # We do not use a cache for unit tests
    # :nocov:
    "#{Digest::SHA256.hexdigest(Rails.application.class.module_parent_name.downcase)}_#{CACHE_NAMESPACE}"
    # :nocov:
  end
end
