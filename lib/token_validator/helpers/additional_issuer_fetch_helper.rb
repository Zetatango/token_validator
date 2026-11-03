# frozen_string_literal: true

require 'active_support/core_ext/numeric/time'
require 'rails'
require 'rest-client'
require 'zlib'

# How machine tokens are obtained from an additional issuer: any trusted issuer other than the
# primary one. Also the fetching machinery AdditionalIssuerSigningKeyHelper uses for that issuer's
# keys.
#
# Every fetch has explicit timeouts, and each failure in FETCH_FAILURES answers nil rather than
# raising. After a failure the same thing is not asked for again for a short while, and within one
# process only one thread fetches a given thing at a time; the threads waiting on it reuse what it
# fetched, from the cache or from this process's own copy.
#
# Kept apart from the primary issuer's path in TokenCacheHelper, which decides which of the two a
# request takes. The primary path stays exactly as it has always behaved, failures included, so
# upgrading changes nothing for a consumer that trusts no other issuer.
module TokenValidator::AdditionalIssuerFetchHelper
  # Seconds allowed to open a connection, and then to read the response, on every fetch. Without
  # them the HTTP client waits about a minute for each.
  FETCH_OPEN_TIMEOUT = 5
  FETCH_READ_TIMEOUT = 10

  # Redirects are never followed: keys and tokens come only from the addresses the issuer entry
  # names. A redirect answers as an HTTP error, one of FETCH_FAILURES.
  FETCH_MAX_REDIRECTS = 0

  # After a failed fetch, how long the same thing -- one token, or one issuer's keys -- is not asked
  # for again. Calls in the meantime answer as the failed fetch did, rather than each waiting on an
  # endpoint that just failed.
  FAILED_FETCH_BACKOFF = 10.seconds

  # The longest lifetime a machine token response may state. A longer one, or one that is not a
  # finite number, is refused rather than believed and cached for that long.
  ACCESS_TOKEN_MAX_LIFETIME = 7.days

  # A response that arrived but cannot be used. Raised and rescued within this module only.
  class UnusableResponse < StandardError; end

  # Every way a fetch is known to fail. The HTTP client wraps HTTP errors and timeouts in its own
  # exceptions, but lets DNS failures, connection resets, TLS and other OpenSSL errors, malformed
  # responses, compressed bodies that cannot be decompressed and broken streams through as they are.
  FETCH_FAILURES = [
    RestClient::Exception, SocketError, SystemCallError, OpenSSL::OpenSSLError, IOError, Net::ProtocolError,
    Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Zlib::Error, JSON::ParserError, UnusableResponse
  ].freeze

  FAILED_FETCH_KEY = 'failed-fetch'

  # Guards the creation of the per-key locks, which every thread in the process shares.
  FLIGHT_LOCKS_GUARD = Mutex.new

  private

  # +audience+ is the API the caller named, or ENTRY_AUDIENCE for the one the entry carries.
  def additional_issuer_access_token(entry, audience)
    return nil unless entry_audience?(audience) ? single_entry_audience?(entry) : requestable_audience?(audience)
    return request_additional_access_token(entry, audience) if Rails.cache.nil?

    cache_key = access_token_cache_key(entry[:issuer_url], audience)

    cached_access_token(cache_key) || single_flight(cache_key) do
      # Re-read inside the lock: a thread that waited here finds the token the one before it fetched.
      cached_access_token(cache_key) || obtain_access_token(entry, audience, cache_key)
    end
  end

  # The shared cache's token, else this process's copy of the last one it fetched.
  def cached_access_token(cache_key)
    Rails.cache.read(cache_key, namespace:) || kept_in_process(cache_key)
  end

  def obtain_access_token(entry, audience, cache_key)
    return nil if backing_off?(cache_key)

    token = request_additional_access_token(entry, audience)
    token.nil? ? back_off(cache_key) : keep_access_token(cache_key, token)
    token
  end

  # In the shared cache, and in this process for when the cache keeps nothing, both until
  # ACCESS_TOKEN_EXPIRY_MARGIN before the token expires.
  def keep_access_token(cache_key, token)
    store_access_token(cache_key, token)
    keep_in_process(cache_key, token, token[:expires_in] - TokenValidator::TokenCacheHelper::ACCESS_TOKEN_EXPIRY_MARGIN)
  end

  def request_additional_access_token(entry, audience)
    access_token_from(fetch_json_object(:post, token_endpoint_for(entry), access_token_params(entry, audience)))
  rescue *FETCH_FAILURES => e
    report_failed_fetch(entry_audience?(audience) ? 'a machine token' : "a machine token for #{audience.inspect}", entry, e)
    nil
  end

  def access_token_from(response)
    token = response['access_token']
    expires_in = response['expires_in']
    raise UnusableResponse, 'the token response has no access_token' unless token.is_a?(String) && !token.empty?
    raise UnusableResponse, 'the token response has no numeric expires_in' unless expires_in.is_a?(Numeric)
    raise UnusableResponse, unusable_lifetime_message unless usable_lifetime?(expires_in)

    { token:, expires: Time.now.to_i + expires_in, expires_in: }
  end

  # A token is cached, and handed out, until ACCESS_TOKEN_EXPIRY_MARGIN before it expires. One that
  # lives no longer than that could never be handed out, and its cache expiry would not be positive.
  # A lifetime past ACCESS_TOKEN_MAX_LIFETIME, infinity included, is not believed.
  def usable_lifetime?(expires_in)
    expires_in > TokenValidator::TokenCacheHelper::ACCESS_TOKEN_EXPIRY_MARGIN && expires_in <= ACCESS_TOKEN_MAX_LIFETIME
  end

  def unusable_lifetime_message
    "the token lifetime must be more than #{TokenValidator::TokenCacheHelper::ACCESS_TOKEN_EXPIRY_MARGIN.inspect} " \
      "and at most #{ACCESS_TOKEN_MAX_LIFETIME.inspect}"
  end

  def fetch_json_object(method, url, payload = nil)
    body = RestClient::Request.execute(method:, url:, payload:, open_timeout: FETCH_OPEN_TIMEOUT, read_timeout: FETCH_READ_TIMEOUT,
                                       max_redirects: FETCH_MAX_REDIRECTS)
    response = JSON.parse(body)
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

  # An entry may list several audiences, so that tokens naming any of them verify. A token is asked
  # for one API only, so a caller of such an entry must name the one it wants.
  def single_entry_audience?(entry)
    !entry[:audience].is_a?(Array)
  end

  # Shared through the cache, so one process's failure holds back every process for the backoff.
  # The process's own copy holds it within the process -- and lets threads waiting on a fetch that
  # failed share its answer -- when the cache keeps nothing.
  def backing_off?(cache_key)
    marker = failed_fetch_key(cache_key)
    marked_in_process?(marker) || Rails.cache.exist?(marker, namespace:)
  end

  def back_off(cache_key)
    marker = failed_fetch_key(cache_key)
    mark_in_process(marker, FAILED_FETCH_BACKOFF)
    Rails.cache.write(marker, true, namespace:, expires_in: FAILED_FETCH_BACKOFF)
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
  # carried, since a body can echo a credential. An audience comes from the caller, so it is logged
  # quoted and escaped, which keeps it on the one line.
  def report_failed_fetch(what, entry, error)
    reason = error.is_a?(UnusableResponse) ? error.message : error.class.name
    TokenValidator::ValidatorConfig.logger.error("Could not fetch #{what} from #{entry[:issuer_url]}: #{reason}")
  end
end
