# frozen_string_literal: true

require 'active_support/core_ext/numeric/time'
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
  # keys again. The key id and the issuer come from a token not yet verified, so the limit keeps an
  # issuer's key fetches to this rate whatever key ids incoming tokens name.
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
  #
  # During a backoff nothing is fetched and the answer is nil, as it was for the fetch that failed.
  # The refetch slot is left alone then, so a rotated key can be fetched as soon as the backoff ends.
  def refetched_additional_signing_key(entry)
    return download_additional_signing_key(entry) if Rails.cache.nil?

    jwks_key = jwks_cache_key(entry[:issuer_url])
    single_flight(jwks_key) do
      next nil if backing_off?(jwks_key)

      refetch_allowed?(entry) ? refresh_signing_key(entry) : cached_signing_key(entry)
    end
  end

  # What clearing an additional issuer's keys does: the refetch made for an unknown key id, under the
  # same limit, so the keys valid callers rely on stay in place unless a fetch replaces them. Without
  # a cache there is nothing to clear, and nothing is fetched.
  def cleared_additional_signing_key(entry)
    refetched_additional_signing_key(entry) unless Rails.cache.nil?
  end

  # One thread refreshes; the others carry on with the stale set rather than wait, since it still
  # verifies every token signed by a key the issuer has not withdrawn. The thread that takes the lock
  # looks again first, in case another finished a refresh after this one found the set stale.
  #
  # The lock is taken with interrupts held back, so an exception raised into this thread (a request
  # timeout, say) arrives only once taking it has been recorded, and the ensure then releases it.
  def refresh_stale_signing_key(entry, stale_keys)
    lock = flight_lock(jwks_cache_key(entry[:issuer_url]))
    locked = false
    Thread.handle_interrupt(Object => :never) { locked = lock.try_lock }
    return stale_keys unless locked

    fresh_signing_key(entry) || refresh_signing_key(entry) || stale_keys
  ensure
    lock.unlock if locked
  end

  # Fetches the issuer's keys and, only when that succeeds, replaces the cached set with them. A
  # failure starts the backoff and leaves whatever was cached alone.
  def refresh_signing_key(entry)
    jwks_key = jwks_cache_key(entry[:issuer_url])
    return nil if backing_off?(jwks_key)

    keys = download_additional_signing_key(entry)
    keys ? keep_signing_key(entry, keys) : back_off(jwks_key)
    keys
  end

  # In the shared cache, and in this process for when the cache keeps nothing: the set for
  # SIGNING_KEY_MAX_AGE, and the mark that it is fresh for SIGNING_KEY_REFRESH_AFTER.
  def keep_signing_key(entry, keys)
    jwks_key = jwks_cache_key(entry[:issuer_url])
    Rails.cache.write(jwks_key, keys, namespace:, expires_in: SIGNING_KEY_MAX_AGE)
    Rails.cache.write(jwks_fresh_key(entry), true, namespace:, expires_in: SIGNING_KEY_REFRESH_AFTER)
    keep_in_process(jwks_key, keys, SIGNING_KEY_MAX_AGE)
    mark_in_process(jwks_fresh_key(entry), SIGNING_KEY_REFRESH_AFTER)
  end

  # The shared cache's set, else this process's copy of the last one it fetched. The shared set comes
  # first, so keys another process fetched after a rotation are found here too. An empty set counts
  # as nothing cached, so it is fetched again. This library never caches one, but an earlier release
  # sharing the cache can, from a key set that listed no keys.
  def cached_signing_key(entry)
    jwks_key = jwks_cache_key(entry[:issuer_url])
    Rails.cache.read(jwks_key, namespace:).presence || kept_in_process(jwks_key)
  end

  def fresh_signing_key(entry)
    cached_signing_key(entry) if signing_key_fresh?(entry)
  end

  def signing_key_fresh?(entry)
    fresh_key = jwks_fresh_key(entry)
    Rails.cache.exist?(fresh_key, namespace:) || marked_in_process?(fresh_key)
  end

  # Takes the issuer's refetch slot for the next JWKS_REFETCH_COOLDOWN, in the cache shared with
  # other processes and then in this process. The process's own slot holds the limit when the cache
  # keeps nothing. It is taken only once the shared slot is won, so a slot another process holds never
  # keeps this one waiting past that slot's end. A cache that refuses the write answers no, which is
  # the safe direction: the token is refused and the cached keys stand.
  def refetch_allowed?(entry)
    marker = jwks_refetch_key(entry)
    return false if marked_in_process?(marker)
    return false unless Rails.cache.write(marker, true, namespace:, unless_exist: true, expires_in: JWKS_REFETCH_COOLDOWN)

    mark_in_process(marker, JWKS_REFETCH_COOLDOWN)
    true
  end

  def download_additional_signing_key(entry)
    key_set_from(fetch_json_object(:get, entry[:jwks_url]), entry)
  rescue *TokenValidator::AdditionalIssuerFetchHelper::FETCH_FAILURES => e
    report_failed_fetch('signing keys', entry, e)
    nil
  end

  # Keeps only the keys that can verify a signature. One published in a shape this library cannot
  # use is left out, so a token naming it is refused like any unknown key rather than raising. That
  # includes a shared-secret key, which converts to a string rather than to a public key.
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

    JSON::JWK.new(key).to_key.is_a?(OpenSSL::PKey::PKey)
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
