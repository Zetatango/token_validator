# frozen_string_literal: true

require 'rails'
require 'rest-client'

module TokenValidator::TokenCacheHelper
  protected

  CACHE_NAMESPACE = 'oauth_token_service'
  ISSUER_JWKS_KEY = 'issuer-jwks'
  ACCESS_TOKEN = 'access-token'

  # How long before its real expiry a cached machine token stops being handed out, so a caller is
  # never given one that lapses on its way to the receiving service.
  ACCESS_TOKEN_EXPIRY_MARGIN = 3.minutes

  # The default for +audience:+ on the machine-token calls, meaning "the audience the issuer entry
  # names". A sentinel rather than nil, so that only a caller who leaves the keyword out gets that
  # audience. A caller passing nil -- typically a setting that was never configured -- is asking for
  # an audience it does not have, and is given no token rather than one for a different API.
  ENTRY_AUDIENCE = Object.new.freeze

  # A machine token for +issuer+, or for the primary issuer when none is given.
  #
  # +audience+ names the API the token is to be accepted by. Omitted, it is the one the issuer entry
  # carries, which is the only token there was before a caller could choose. Only an additional
  # issuer can be asked for a particular audience. The primary issuer is never sent one, so asking it
  # for one answers nil rather than a token for some other API.
  #
  # THE TWO KINDS OF ISSUER ARE FETCHED FROM SEPARATELY. The primary issuer's path, here, is the one
  # this library has always had. Every other issuer goes through AdditionalIssuerFetchHelper.
  def fetch_access_token(issuer = nil, audience: ENTRY_AUDIENCE)
    entry = issuer_entry_for(issuer)
    return nil if entry.nil? || !machine_token_credentials?(entry)
    return additional_issuer_access_token(entry, audience) unless primary_issuer?(entry)
    return nil unless entry_audience?(audience)

    token = primary_access_token(entry)

    # Scratch state on a Singleton, so only the primary issuer touches it. Letting an additional
    # issuer write here would be precisely the shared mutable state per-issuer isolation forbids.
    @access_token = token if issuer.nil?

    token
  end

  # The signing keys for +issuer+, or for the primary issuer when none is given.
  #
  # Keys are held per issuer, and that isolation is the point of this method rather than an
  # optimisation. With one shared slot, keys downloaded for one issuer could be handed back to
  # verify a token claiming a different one -- so a caller must never be able to reach issuer A's
  # keys by asking for issuer B.
  def fetch_signing_key(issuer = nil)
    entry = issuer_entry_for(issuer)

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

  # Drops just +issuer+'s cached signing keys.
  #
  # Deliberately not +clear+. A token naming a +kid+ we have not seen usually means its issuer
  # rotated keys, and re-reading that one issuer's JWKS is the whole remedy. Clearing the namespace
  # instead would let an unknown +kid+ -- a value the token controls, on a request that has not been
  # authenticated yet -- evict every *other* issuer's keys and machine tokens, turning a bad token
  # into a cache flush and a round of refetches.
  def evict_signing_key(issuer = nil)
    entry = issuer_entry_for(issuer)
    return if entry.nil?

    Rails.cache&.delete(jwks_cache_key(entry[:issuer_url]), namespace:)
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

  # The primary issuer's machine token, from the cache or else requested.
  def primary_access_token(entry)
    cache_key = access_token_cache_key(entry[:issuer_url])

    Rails.cache&.read(cache_key, namespace:) || request_access_token(cache_key)
  end

  # Posts to the exact endpoint the primary issuer has always used, double slash and all.
  def request_access_token(cache_key)
    # Parsed once. The previous version parsed the same body three times, and guarded a literal
    # hash against being nil; both are dropped here without any change in behaviour.
    response = JSON.parse(RestClient.post(oauth_path(:token), primary_access_token_params))

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

  def store_access_token(cache_key, access_token)
    Rails.cache&.write(cache_key, access_token, namespace:, expires_in: access_token[:expires_in] - ACCESS_TOKEN_EXPIRY_MARGIN)
  end

  def oauth_path(action)
    "#{TokenValidator::ValidatorConfig.config[:issuer_url]}/oauth/#{action}"
  end

  private

  # Byte-identical to what this library has always sent, including the absence of +audience+.
  def primary_access_token_params
    { grant_type: :client_credentials,
      client_id: TokenValidator::ValidatorConfig.config[:client_id],
      client_secret: TokenValidator::ValidatorConfig.config[:client_secret],
      scope: TokenValidator::ValidatorConfig.config[:requested_scope] }
  end

  # An issuer configured only so that its tokens can be *verified* carries no machine-token
  # credentials. Asking it for a token must yield nothing rather than quietly falling back to the
  # primary issuer's credentials, which would post our client secret to somebody else's endpoint.
  def machine_token_credentials?(entry)
    return true if primary_issuer?(entry)

    entry[:client_id].present? && entry[:client_secret].present?
  end

  def primary_issuer?(entry)
    entry[:issuer_url] == TokenValidator::ValidatorConfig.config[:issuer_url]
  end

  # Whether a caller left +audience:+ out, and so wants the audience the issuer entry carries.
  def entry_audience?(audience)
    audience.equal?(ENTRY_AUDIENCE)
  end

  # An omitted issuer means the primary one, which is what every caller wanted before this library
  # knew about more than one.
  #
  # +nil+ and not +blank?+, deliberately. An empty or whitespace issuer is a *named* issuer that
  # happens to be blank -- typically a token whose +iss+ claim is empty or missing -- and
  # ValidatorConfig rejects exactly that. Treating blank as absent here would route around that
  # guard and hand back the primary issuer's keys, which is the cross-issuer confusion this
  # per-issuer lookup exists to prevent.
  def issuer_entry_for(issuer)
    issuer = TokenValidator::ValidatorConfig.config[:issuer_url] if issuer.nil?

    TokenValidator::ValidatorConfig.issuer_config_for(issuer)
  end

  def jwks_cache_key(issuer_url)
    issuer_scoped_key(ISSUER_JWKS_KEY, issuer_url)
  end

  # A token asked for by audience is held apart from the entry's own, and from every other
  # audience's. The key for the entry's own audience is the one it has always been, so processes
  # still running an earlier release share it.
  def access_token_cache_key(issuer_url, audience = ENTRY_AUDIENCE)
    key = issuer_scoped_key(ACCESS_TOKEN, issuer_url)
    return key if entry_audience?(audience)

    "#{key}-#{Digest::SHA256.hexdigest(audience)}"
  end

  # Digested because an issuer URL is not safe to paste into a cache key, and because it keeps the
  # key a fixed length whatever the issuer. Any per-issuer key works; a shared one does not.
  def issuer_scoped_key(prefix, issuer_url)
    "#{prefix}-#{Digest::SHA256.hexdigest(issuer_url)}"
  end

  def namespace
    # We do not use a cache for unit tests
    # :nocov:
    "#{Digest::SHA256.hexdigest(Rails.application.class.module_parent_name.downcase)}_#{CACHE_NAMESPACE}"
    # :nocov:
  end
end
