# frozen_string_literal: true

require 'rails'
require 'rest-client'

# How machine tokens are obtained from an additional issuer: any trusted issuer other than the
# primary one.
#
# Kept apart from the primary issuer's path in TokenCacheHelper, which decides which of the two a
# request takes. The primary path stays exactly as it has always behaved, so upgrading changes
# nothing for a consumer that trusts no other issuer.
module TokenValidator::AdditionalIssuerFetchHelper
  private

  # +audience+ is the API the caller named, or ENTRY_AUDIENCE for the one the entry carries.
  def additional_issuer_access_token(entry, audience)
    return nil unless entry_audience?(audience) || requestable_audience?(audience)

    cache_key = access_token_cache_key(entry[:issuer_url], audience)

    Rails.cache&.read(cache_key, namespace:) || request_additional_access_token(entry, audience, cache_key)
  end

  def request_additional_access_token(entry, audience, cache_key)
    response = JSON.parse(RestClient.post(token_endpoint_for(entry), access_token_params(entry, audience)))

    access_token = {
      token: response['access_token'],
      expires: Time.now.to_i + response['expires_in'],
      expires_in: response['expires_in']
    }

    store_access_token(cache_key, access_token)

    access_token
  rescue Errno::ECONNREFUSED, RestClient::Exception
    nil
  end

  # Auth0 publishes its token endpoint at <domain>/oauth/token. +token_url+ overrides that for
  # anything non-standard.
  def token_endpoint_for(entry)
    entry[:token_url].presence || "#{entry[:issuer_url].chomp('/')}/oauth/token"
  end

  # Auth0 requires +audience+ on a client-credentials grant. Without it the token comes back for the
  # tenant's own management API rather than for ours.
  def access_token_params(entry, audience)
    { grant_type: :client_credentials,
      client_id: entry[:client_id],
      client_secret: entry[:client_secret],
      audience: entry_audience?(audience) ? entry[:audience] : audience }
  end

  # A named audience must be a non-blank String. Anything else names no API, and is refused rather
  # than replaced with the entry's audience.
  def requestable_audience?(audience)
    audience.is_a?(String) && !audience.strip.empty?
  end
end
