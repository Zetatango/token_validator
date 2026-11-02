# frozen_string_literal: true

require 'json/jwt'
require 'rails'

# How an additional issuer's signing keys are fetched and kept: any trusted issuer other than the
# primary one.
#
# Keys are fetched with the timeouts and failure handling of AdditionalIssuerFetchHelper, and a
# fetched set replaces the cached one only when the fetch succeeded. A token naming a key id the
# cached set lacks can make this library fetch an issuer's keys again at most once a minute. Cached
# keys are refreshed hourly, so a key the issuer has withdrawn stops being trusted.
#
# The primary issuer's keys do not come through here; TokenCacheHelper keeps their path exactly as
# it has always been.
module TokenValidator::AdditionalIssuerSigningKeyHelper
  # How often a token naming a key id the cached set lacks may make this library fetch an issuer's
  # keys again. The key id and the issuer both come from a token nobody has authenticated yet, so
  # without a limit anyone could turn every request into a fetch.
  JWKS_REFETCH_COOLDOWN = 1.minute

  # Cached keys are fetched again once they are this old. When that fetch fails the cached set stays
  # in use, so a brief outage at the issuer refuses nobody, but never beyond SIGNING_KEY_MAX_AGE.
  SIGNING_KEY_REFRESH_AFTER = 1.hour
  SIGNING_KEY_MAX_AGE = 24.hours

  # Every way json-jwt was seen to fail turning a published key into one that can verify a signature.
  KEY_CONVERSION_FAILURES = [JSON::JWT::Exception, OpenSSL::OpenSSLError, ArgumentError, TypeError, NoMethodError].freeze

  JWKS_FRESH_KEY = 'issuer-jwks-fresh'
  JWKS_REFETCH_KEY = 'issuer-jwks-refetch'

  private

  # The cached set while it is fresh. A stale set is refreshed; with nothing cached, threads in this
  # process wait for one fetch.
  def additional_issuer_signing_key(entry)
    return download_additional_signing_key(entry) if Rails.cache.nil?

    keys = cached_signing_key(entry)
    return keys if keys && signing_key_fresh?(entry)
    return refresh_stale_signing_key(entry, keys) if keys

    single_flight(jwks_cache_key(entry[:issuer_url])) { cached_signing_key(entry) || refresh_signing_key(entry) }
  end

  # For a token naming a key id the cached set lacks, which usually means the issuer rotated its keys.
  # Fetched again at most once per JWKS_REFETCH_COOLDOWN per issuer, across every process sharing the
  # cache; inside the cooldown the cached set is answered as it stands. A failed fetch answers nil and
  # leaves the cached set in place, so it can never cost valid tokens their keys.
  def refetched_additional_signing_key(entry)
    return download_additional_signing_key(entry) if Rails.cache.nil?

    single_flight(jwks_cache_key(entry[:issuer_url])) do
      refetch_allowed?(entry) ? refresh_signing_key(entry) : cached_signing_key(entry)
    end
  end

  # One thread refreshes; the others carry on with the stale set rather than wait, since it still
  # verifies every token signed by a key the issuer has not withdrawn.
  def refresh_stale_signing_key(entry, stale_keys)
    lock = flight_lock(jwks_cache_key(entry[:issuer_url]))
    return stale_keys unless lock.try_lock

    begin
      refresh_signing_key(entry) || stale_keys
    ensure
      lock.unlock
    end
  end

  # Fetches the issuer's keys and, only when that succeeds, replaces the cached set with them. A
  # failure starts the backoff and leaves whatever was cached alone.
  def refresh_signing_key(entry)
    jwks_key = jwks_cache_key(entry[:issuer_url])
    return nil if backing_off?(jwks_key)

    keys = download_additional_signing_key(entry)
    if keys
      Rails.cache.write(jwks_key, keys, namespace:, expires_in: SIGNING_KEY_MAX_AGE)
      Rails.cache.write(jwks_fresh_key(entry), true, namespace:, expires_in: SIGNING_KEY_REFRESH_AFTER)
    else
      back_off(jwks_key)
    end
    keys
  end

  # +presence+, because a release before this one cached nil when a fetch failed.
  def cached_signing_key(entry)
    Rails.cache.read(jwks_cache_key(entry[:issuer_url]), namespace:).presence
  end

  def signing_key_fresh?(entry)
    Rails.cache.exist?(jwks_fresh_key(entry), namespace:)
  end

  # Takes the issuer's refetch slot for the next JWKS_REFETCH_COOLDOWN. A cache that cannot record
  # the slot answers no, which is the safe direction: the token is refused and the cached keys stand.
  def refetch_allowed?(entry)
    Rails.cache.write(jwks_refetch_key(entry), true, namespace:, unless_exist: true, expires_in: JWKS_REFETCH_COOLDOWN)
  end

  def download_additional_signing_key(entry)
    key_set_from(fetch_json_object(:get, entry[:jwks_url]), entry)
  rescue *TokenValidator::AdditionalIssuerFetchHelper::FETCH_FAILURES => e
    report_failed_fetch('signing keys', entry, e)
    nil
  end

  # Keeps only the keys that can verify a signature. One published in a shape this library cannot
  # use is left out, so a token naming it is refused like any unknown key rather than raising.
  def key_set_from(response, entry)
    keys = response['keys']
    raise TokenValidator::AdditionalIssuerFetchHelper::UnusableResponse, 'the key set has no list of keys' unless keys.is_a?(Array)

    usable = keys.select { |key| usable_signing_key?(key) }
    raise TokenValidator::AdditionalIssuerFetchHelper::UnusableResponse, 'the key set has no usable key' if usable.empty?

    report_unusable_signing_keys(entry, keys.size - usable.size)
    JSON::JWK::Set.new(usable)
  end

  def usable_signing_key?(key)
    return false unless key.is_a?(Hash)

    JSON::JWK.new(key).to_key
    true
  rescue *KEY_CONVERSION_FAILURES
    false
  end

  def report_unusable_signing_keys(entry, count)
    return if count.zero?

    TokenValidator::ValidatorConfig.logger.error("Ignored #{count} unusable signing key(s) from #{entry[:issuer_url]}")
  end

  def jwks_fresh_key(entry)
    issuer_scoped_key(JWKS_FRESH_KEY, entry[:issuer_url])
  end

  def jwks_refetch_key(entry)
    issuer_scoped_key(JWKS_REFETCH_KEY, entry[:issuer_url])
  end
end
