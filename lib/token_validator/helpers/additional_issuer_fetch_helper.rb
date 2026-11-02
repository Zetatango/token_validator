# frozen_string_literal: true

require 'rails'
require 'rest-client'

# How machine tokens are obtained from an additional issuer: any trusted issuer other than the
# primary one.
#
# Every fetch has explicit timeouts, and every way it can fail answers nil rather than raising. After
# a failure the same thing is not asked for again for a short while, and within one process only one
# thread fetches a given token at a time.
#
# Kept apart from the primary issuer's path in TokenCacheHelper, which decides which of the two a
# request takes. The primary path stays exactly as it has always behaved, failures included, so
# upgrading changes nothing for a consumer that trusts no other issuer.
module TokenValidator::AdditionalIssuerFetchHelper
  # Seconds allowed to open a connection, and then to read the response, on every fetch. Without
  # them the HTTP client waits about a minute for each.
  FETCH_OPEN_TIMEOUT = 5
  FETCH_READ_TIMEOUT = 10

  # After a failed fetch, how long the same token is not asked for again. Calls in the meantime
  # answer nil, as the failed fetch did, rather than each waiting on an endpoint that just failed.
  FAILED_FETCH_BACKOFF = 10.seconds

  # A response that arrived but cannot be used. Raised and rescued within this module only.
  class UnusableResponse < StandardError; end

  # Every way a fetch is known to fail. The HTTP client wraps HTTP errors and timeouts in its own
  # exceptions, but lets DNS failures, connection resets, TLS errors and broken streams through as
  # they are.
  FETCH_FAILURES = [
    RestClient::Exception, SocketError, SystemCallError, OpenSSL::SSL::SSLError, IOError, JSON::ParserError, UnusableResponse
  ].freeze

  FAILED_FETCH_KEY = 'failed-fetch'

  # Guards the creation of the per-key locks, which every thread in the process shares.
  FLIGHT_LOCKS_GUARD = Mutex.new

  private

  # +audience+ is the API the caller named, or ENTRY_AUDIENCE for the one the entry carries.
  def additional_issuer_access_token(entry, audience)
    return nil unless entry_audience?(audience) || requestable_audience?(audience)
    return request_additional_access_token(entry, audience) if Rails.cache.nil?

    cache_key = access_token_cache_key(entry[:issuer_url], audience)

    cached_access_token(cache_key) || single_flight(cache_key) do
      # Re-read inside the lock: a thread that waited here finds the token the one before it fetched.
      cached_access_token(cache_key) || obtain_access_token(entry, audience, cache_key)
    end
  end

  def cached_access_token(cache_key)
    Rails.cache.read(cache_key, namespace:)
  end

  def obtain_access_token(entry, audience, cache_key)
    return nil if backing_off?(cache_key)

    token = request_additional_access_token(entry, audience)
    token.nil? ? back_off(cache_key) : store_access_token(cache_key, token)
    token
  end

  def request_additional_access_token(entry, audience)
    access_token_from(fetch_json_object(:post, token_endpoint_for(entry), access_token_params(entry, audience)))
  rescue *FETCH_FAILURES => e
    report_failed_fetch(entry_audience?(audience) ? 'a machine token' : "a machine token for #{audience}", entry, e)
    nil
  end

  def access_token_from(response)
    token = response['access_token']
    expires_in = response['expires_in']
    raise UnusableResponse, 'the token response has no access_token' unless token.is_a?(String) && !token.empty?
    raise UnusableResponse, 'the token response has no numeric expires_in' unless expires_in.is_a?(Numeric)

    { token:, expires: Time.now.to_i + expires_in, expires_in: }
  end

  def fetch_json_object(method, url, payload = nil)
    response = JSON.parse(
      RestClient::Request.execute(method:, url:, payload:, open_timeout: FETCH_OPEN_TIMEOUT, read_timeout: FETCH_READ_TIMEOUT)
    )
    raise UnusableResponse, 'the response is not a JSON object' unless response.is_a?(Hash)

    response
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

  # Shared through the cache, so one process's failure holds back every process for the backoff.
  def backing_off?(cache_key)
    Rails.cache.exist?(failed_fetch_key(cache_key), namespace:)
  end

  def back_off(cache_key)
    Rails.cache.write(failed_fetch_key(cache_key), true, namespace:, expires_in: FAILED_FETCH_BACKOFF)
  end

  def failed_fetch_key(cache_key)
    "#{FAILED_FETCH_KEY}-#{cache_key}"
  end

  # Runs the block holding the lock for +key+, so threads in this process that need the same thing
  # wait for one fetch of it instead of each making their own. Another key is never held up.
  def single_flight(key, &)
    flight_lock(key).synchronize(&)
  end

  def flight_lock(key)
    FLIGHT_LOCKS_GUARD.synchronize { (@flight_locks ||= {})[key] ||= Mutex.new }
  end

  # Names the error's class, or what was wrong with a response, and never anything the response
  # carried, since a body can echo a credential.
  def report_failed_fetch(what, entry, error)
    reason = error.is_a?(UnusableResponse) ? error.message : error.class.name
    TokenValidator::ValidatorConfig.logger.error("Could not fetch #{what} from #{entry[:issuer_url]}: #{reason}")
  end
end
