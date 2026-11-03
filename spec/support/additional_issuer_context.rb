# frozen_string_literal: true

# One primary issuer, one additional issuer that can be asked for machine tokens and whose signing
# keys are fetched, and an in-memory cache. Shared by the specs that exercise how those fetches
# behave under failures, time and concurrency.
module AdditionalIssuerContext
  Application = Class.new

  PRIMARY_ISSUER = 'https://idp.example.com/'
  PRIMARY_TOKEN_URL = 'https://idp.example.com//oauth/token'
  PRIMARY_JWKS_URL = 'https://idp.example.com//oauth/discovery/keys'
  EXTRA_ISSUER = 'https://tenant.ca.auth0.com/'
  EXTRA_TOKEN_URL = 'https://tenant.ca.auth0.com/oauth/token'
  EXTRA_JWKS_URL = 'https://tenant.ca.auth0.com/.well-known/jwks.json'
  ENTRY_API = 'https://api.example.com/platform'
  ORDERS_API = 'https://api.example.com/orders'
  BILLING_API = 'https://api.example.com/billing'

  MILLISECOND = 0.001

  # Stands for an exception raised into a thread from outside, as a request timeout does. Not a
  # StandardError, so nothing rescues it by accident.
  class RequestCutShort < Exception; end # rubocop:disable Lint/InheritException

  SIGNING_KEYS = Hash.new { |keys, kid| keys[kid] = OpenSSL::PKey::RSA.new(2048) }

  # Cache whose writes always report failure and store nothing, as a cache store does when its
  # backend is unreachable and it is configured to swallow errors.
  class WriteRefusingStore < ActiveSupport::Cache::MemoryStore
    protected

    def write_entry(_key, _entry, **) # rubocop:disable Naming/PredicateMethod
      false
    end
  end

  # Cache that behaves as Rails' Redis store does while Redis is unreachable: every read misses and
  # every write reports failure.
  class UnreachableStore < ActiveSupport::Cache::MemoryStore
    protected

    def read_entry(_key, **) = nil

    def write_entry(_key, _entry, **) = false # rubocop:disable Naming/PredicateMethod
  end

  # Cache that turns an expiry into whole milliseconds before storing, as a Redis-backed store does.
  # That arithmetic raises for an infinite expiry, which an in-memory store accepts.
  class MillisecondExpiryStore < ActiveSupport::Cache::MemoryStore
    protected

    def write_entry(key, entry, **options)
      (1000 * options[:expires_in].to_f).ceil if options[:expires_in]
      super
    end
  end
end

RSpec.shared_context 'with an additional issuer' do
  subject(:service) { TokenValidator::OauthTokenService.instance }

  def extra_entry
    { issuer_url: AdditionalIssuerContext::EXTRA_ISSUER, jwks_url: AdditionalIssuerContext::EXTRA_JWKS_URL,
      audience: AdditionalIssuerContext::ENTRY_API, algorithm: 'RS256', client_id: 'extra-client', client_secret: 'extra-secret' }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def use_cache(store = cache)
    allow(Rails).to receive_messages(cache: store, application: AdditionalIssuerContext::Application.new)
  end

  # The cache keys written while the block runs, which must be passed through to the real cache.
  def keys_written_to_cache
    written = []
    allow(cache).to receive(:write).and_wrap_original do |write, key, *rest, **options|
      written << key
      write.call(key, *rest, **options)
    end
    yield
    written
  end

  def log_lines
    @log_lines ||= StringIO.new
  end

  def token_body(value = 'extra-token', expires_in = 86_400)
    { access_token: value, expires_in: }.to_json
  end

  # A token endpoint that answers with a token naming the audience it was asked for, so a caller can
  # tell which request its token came from.
  def stub_token_endpoint_echoing_audience(expires_in: 86_400)
    stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return do |request|
      audience = URI.decode_www_form(request.body).to_h.fetch('audience')
      { status: 200, body: token_body("token-for-#{audience}", expires_in) }
    end
  end

  def token_requests(audience = nil)
    request = a_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL)
    audience ? request.with(body: hash_including('audience' => audience)) : request
  end

  # Every HTTP request made since WebMock was last reset, whatever its target.
  def requests_made
    WebMock::RequestRegistry.instance.requested_signatures.hash.values.sum
  end

  # The threads' results, failing the example if any is still running after +timeout+ seconds, so a
  # deadlock shows as a failure rather than a hung run.
  def values_of(*threads, timeout: 10)
    threads.flatten.map { |thread| thread.join(timeout) ? thread.value : raise("a thread was still running after #{timeout}s") }
  end

  def key_requests
    a_request(:get, AdditionalIssuerContext::EXTRA_JWKS_URL)
  end

  def jwk(kid)
    AdditionalIssuerContext::SIGNING_KEYS[kid].public_key.to_jwk(kid:, use: 'sig', alg: 'RS256')
  end

  def key_set_response(*kids)
    { status: 200, body: { keys: kids.map { |kid| jwk(kid) } }.to_json }
  end

  def kids_of(key_set)
    key_set&.map { |key| key['kid'] }
  end

  def token_for(audience)
    service.access_token(AdditionalIssuerContext::EXTRA_ISSUER, audience:)
  end

  def extra_keys
    service.signing_key(AdditionalIssuerContext::EXTRA_ISSUER)
  end

  def refetched_extra_keys
    service.refetch_signing_key(AdditionalIssuerContext::EXTRA_ISSUER)
  end

  before do
    TokenValidator::ValidatorConfig.configure(
      issuer_url: AdditionalIssuerContext::PRIMARY_ISSUER, client_id: 'primary-client', client_secret: 'primary-secret',
      requested_scope: 'test:scope', audience: 'https://primary.example.com'
    )
    TokenValidator::ValidatorConfig.additional_issuers = [extra_entry]
    service.instance_variable_set(:@access_token, nil)
    service.instance_variable_set(:@flight_locks, nil)
    allow(TokenValidator::ValidatorConfig).to receive(:logger).and_return(Logger.new(log_lines))
  end

  after do
    Timecop.return
    TokenValidator::ValidatorConfig.additional_issuers = []
  end
end

# Tokens signed with a key the primary issuer publishes, and the means to verify them.
RSpec.shared_context 'with signed tokens' do
  def primary_signing_key
    AdditionalIssuerContext::SIGNING_KEYS['primary-signing-key']
  end

  def primary_key_set
    { status: 200, body: { keys: [primary_signing_key.public_key.to_jwk(kid: 'primary-kid', use: 'sig', alg: 'RS512')] }.to_json }
  end

  def primary_token(kid: 'primary-kid')
    claims = { sub: 'subject', iat: Time.now.to_i, exp: (Time.now + 30.minutes).to_i, iss: AdditionalIssuerContext::PRIMARY_ISSUER,
               aud: 'https://primary.example.com', scopes: ['test:api'], kid: }
    JWT.encode(claims, primary_signing_key, 'RS512')
  end

  def validates?(token)
    TokenValidator::TokenService.new(token, ['test:api']).valid_access_token?
  end

  before { TokenValidator::TokenService.clear }
end
