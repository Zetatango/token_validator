# frozen_string_literal: true

require 'spec_helper'

# How a machine token is fetched from an additional issuer: within explicit timeouts, answering nil
# for every way the fetch can fail, holding back after a failure, and one fetch at a time per
# process for callers that need the same token.
module TokenValidatorTokenFetchSpec
  Application = Class.new

  # Turns an expiry into whole milliseconds before storing, as Rails' Redis store does. That
  # arithmetic raises for an infinite expiry, which an in-memory store keeps as it is.
  class MillisecondExpiryStore < ActiveSupport::Cache::MemoryStore
    protected

    def write_entry(key, entry, **options)
      (1000 * options[:expires_in].to_f).ceil if options[:expires_in]
      super
    end
  end
end

RSpec.describe TokenValidator::OauthTokenService do
  subject(:service) { described_class.instance }

  def primary_issuer = 'https://idp.example.com/'
  def primary_token_url = 'https://idp.example.com//oauth/token'
  def auth0_issuer = 'https://tenant.ca.auth0.com/'
  def auth0_token_url = 'https://tenant.ca.auth0.com/oauth/token'
  def orders_api = 'https://api.example.com/orders'
  def billing_api = 'https://api.example.com/billing'

  def auth0_entry
    { issuer_url: auth0_issuer, jwks_url: "#{auth0_issuer}.well-known/jwks.json", audience: 'https://api.example.com/platform',
      algorithm: 'RS256', client_id: 'auth0-client', client_secret: 'auth0-secret' }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def with_cache
    allow(Rails).to receive_messages(cache:, application: TokenValidatorTokenFetchSpec::Application.new)
  end

  def token_body(value = 'auth0-token', expires_in: 86_400)
    { access_token: value, expires_in: }.to_json
  end

  def token_for(audience)
    service.access_token(auth0_issuer, audience:)
  end

  def requests_for(audience)
    a_request(:post, auth0_token_url).with(body: hash_including(audience:))
  end

  def log_lines
    @log_lines ||= StringIO.new
  end

  def unusable_lifetime = 'the token lifetime must be more than 3 minutes and at most 7 days'

  # A cache that keeps nothing, as a null store does and as Rails' Redis store does while Redis is
  # unreachable.
  def with_a_cache_that_keeps_nothing
    allow(Rails).to receive_messages(cache: ActiveSupport::Cache::NullStore.new, application: TokenValidatorTokenFetchSpec::Application.new)
  end

  before do
    TokenValidator::ValidatorConfig.configure(
      issuer_url: primary_issuer, client_id: 'primary-client', client_secret: 'primary-secret',
      requested_scope: 'test:scope', audience: 'https://primary.example.com'
    )
    TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry]
    allow(TokenValidator::ValidatorConfig).to receive(:logger).and_return(Logger.new(log_lines))
  end

  after { Timecop.return }

  describe 'timeouts' do
    it 'gives the HTTP client explicit open and read timeouts' do
      allow(RestClient::Request).to receive(:execute).and_call_original
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body)

      token_for(orders_api)

      expect(RestClient::Request).to have_received(:execute)
        .with(hash_including(method: :post, open_timeout: 5, read_timeout: 10))
    end

    it 'gives the same timeouts to a token asked for without an audience' do
      allow(RestClient::Request).to receive(:execute).and_call_original
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body)

      service.access_token(auth0_issuer)

      expect(RestClient::Request).to have_received(:execute).with(hash_including(open_timeout: 5, read_timeout: 10))
    end
  end

  # Each of these failures answers nil -- and an empty header -- rather than raising into the caller.
  describe 'a failed fetch' do
    {
      'a DNS failure' => ->(stub) { stub.to_raise(SocketError) },
      'a connection reset' => ->(stub) { stub.to_raise(Errno::ECONNRESET) },
      'an unreachable host' => ->(stub) { stub.to_raise(Errno::EHOSTUNREACH) },
      'a TLS failure' => ->(stub) { stub.to_raise(OpenSSL::SSL::SSLError) },
      'another OpenSSL failure' => ->(stub) { stub.to_raise(OpenSSL::OpenSSLError) },
      'an HTTP protocol error' => ->(stub) { stub.to_raise(Net::ProtocolError) },
      'a malformed response' => ->(stub) { stub.to_raise(Net::HTTPBadResponse) },
      'a malformed response header' => ->(stub) { stub.to_raise(Net::HTTPHeaderSyntaxError) },
      'a corrupt compressed body' => ->(stub) { stub.to_raise(Zlib::DataError) },
      'a truncated compressed body' => ->(stub) { stub.to_raise(Zlib::BufError) },
      'a broken stream' => ->(stub) { stub.to_raise(IOError) },
      'a timeout' => lambda(&:to_timeout),
      'a refusal' => ->(stub) { stub.to_return(status: 401) },
      'a server error' => ->(stub) { stub.to_return(status: 500) },
      'a body that is not JSON' => ->(stub) { stub.to_return(status: 200, body: '<html>maintenance</html>') },
      'a body that is a JSON list' => ->(stub) { stub.to_return(status: 200, body: '[]') },
      'a body that is JSON null' => ->(stub) { stub.to_return(status: 200, body: 'null') },
      'a body with no access_token' => ->(stub) { stub.to_return(status: 200, body: { expires_in: 86_400 }.to_json) },
      'a body with an empty access_token' => ->(stub) { stub.to_return(status: 200, body: token_body('')) },
      'a body with no expires_in' => ->(stub) { stub.to_return(status: 200, body: { access_token: 't' }.to_json) },
      'a body whose expires_in is not a number' => ->(stub) { stub.to_return(status: 200, body: { access_token: 't', expires_in: '86400' }.to_json) },
      'a token that lives only the three minutes held back' => ->(stub) { stub.to_return(status: 200, body: token_body(expires_in: 180)) },
      'a token with no lifetime left' => ->(stub) { stub.to_return(status: 200, body: token_body(expires_in: 0)) }
    }.each do |failure, respond|
      it "answers nil, and an empty header, for #{failure}" do
        instance_exec(stub_request(:post, auth0_token_url), &respond)

        expect(token_for(orders_api)).to be_nil
        expect(service.oauth_auth_header(auth0_issuer, audience: orders_api)).to eq({})
      end
    end

    [301, 302, 303, 307, 308].each do |status|
      it "answers nil for a #{status} redirect, and never follows it" do
        stub_request(:post, auth0_token_url).to_return(status:, headers: { 'Location' => 'https://elsewhere.example.com/token' })
        elsewhere = stub_request(:any, 'https://elsewhere.example.com/token').to_return(status: 200, body: token_body)

        expect(token_for(orders_api)).to be_nil
        expect(elsewhere).not_to have_been_requested
      end
    end

    it 'logs the issuer, the audience and the kind of failure' do
      stub_request(:post, auth0_token_url).to_raise(SocketError)

      token_for(orders_api)

      expect(log_lines.string).to include("Could not fetch a machine token for #{orders_api} from #{auth0_issuer}: SocketError")
    end

    it 'says what was wrong with a response it could not use' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: { expires_in: 86_400 }.to_json)

      service.access_token(auth0_issuer)

      expect(log_lines.string).to include("Could not fetch a machine token from #{auth0_issuer}: the token response has no access_token")
    end

    it 'never logs what the response carried' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: 'not json: auth0-secret')

      token_for(orders_api)

      expect(log_lines.string).to include('JSON::ParserError')
      expect(log_lines.string).not_to include('auth0-secret')
    end
  end

  # A token is handed out until three minutes before it expires, so one that lives no longer than that
  # could never be handed out. It is refused as unusable, never cached, and starts the backoff.
  describe 'a token that lives three minutes or less' do
    before { with_cache }

    around do |example|
      raise_on_invalid_expiry = ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time
      example.run
    ensure
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = raise_on_invalid_expiry
    end

    it 'is refused at exactly three minutes, and nothing is cached' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 180))

      expect(token_for(orders_api)).to be_nil
      expect(cache.read(service.send(:access_token_cache_key, auth0_issuer, orders_api), namespace: service.send(:namespace))).to be_nil
    end

    it 'counts as a failed fetch, so it is not asked for again within the backoff' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 180))
      token_for(orders_api)

      expect(token_for(orders_api)).to be_nil
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'is accepted, and cached, at one second over' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 181))

      2.times { expect(token_for(orders_api)).to include(token: 'auth0-token', expires_in: 181) }
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'logs that the lifetime is unusable, naming the issuer and the audience' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 60))

      token_for(orders_api)

      expect(log_lines.string)
        .to include("Could not fetch a machine token for #{orders_api} from #{auth0_issuer}: #{unusable_lifetime}")
    end

    it 'does not raise when the cache refuses a negative expiry' do
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = true
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 60))

      expect(token_for(orders_api)).to be_nil
    end

    it 'is not handed out thirty days later by a cache that ignores a negative expiry' do
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = false
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 60))
      token_for(orders_api)

      Timecop.travel(Time.now + 30.days)

      expect(token_for(orders_api)).to be_nil
      expect(requests_for(orders_api)).to have_been_made.twice
    end
  end

  # A lifetime longer than seven days is not believed: the token is refused as unusable rather than
  # cached for as long as the response claims.
  describe 'a token that claims to live longer than seven days' do
    before { with_cache }

    it 'is accepted, and cached, at exactly seven days' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 604_800))

      2.times { expect(token_for(orders_api)).to include(token: 'auth0-token', expires_in: 604_800) }
      expect(requests_for(orders_api)).to have_been_made.once
    end

    [604_801, 604_800.5].each do |lifetime|
      it "is refused at #{lifetime} s, nothing is cached, and it starts the backoff" do
        stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: lifetime))

        expect(token_for(orders_api)).to be_nil
        expect(token_for(orders_api)).to be_nil
        expect(cache.read(service.send(:access_token_cache_key, auth0_issuer, orders_api), namespace: service.send(:namespace))).to be_nil
        expect(requests_for(orders_api)).to have_been_made.once
      end
    end

    it 'logs that the lifetime is unusable' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body(expires_in: 604_801))

      token_for(orders_api)

      expect(log_lines.string).to include("Could not fetch a machine token for #{orders_api} from #{auth0_issuer}: #{unusable_lifetime}")
    end
  end

  # Ruby's JSON parser reads a number too large for a Float, such as 1e999, as Infinity. A token with
  # that lifetime is refused as unusable rather than cached forever or passed to the cache to fail on.
  describe 'a token whose lifetime is not a finite number' do
    before { stub_request(:post, auth0_token_url).to_return(status: 200, body: '{"access_token":"auth0-token","expires_in":1e999}') }

    def with_a_cache_that_counts_milliseconds
      allow(Rails).to receive_messages(cache: TokenValidatorTokenFetchSpec::MillisecondExpiryStore.new,
                                       application: TokenValidatorTokenFetchSpec::Application.new)
    end

    it 'answers nil from a cache that turns an expiry into milliseconds' do
      with_a_cache_that_counts_milliseconds

      expect(token_for(orders_api)).to be_nil
    end

    it 'answers an empty header from a cache that turns an expiry into milliseconds' do
      with_a_cache_that_counts_milliseconds

      expect(service.oauth_auth_header(auth0_issuer, audience: orders_api)).to eq({})
    end

    it 'answers nil, and caches nothing, in a cache that keeps any expiry' do
      with_cache

      expect(token_for(orders_api)).to be_nil
      expect(cache.read(service.send(:access_token_cache_key, auth0_issuer, orders_api), namespace: service.send(:namespace))).to be_nil
    end

    it 'counts as a failed fetch, so it is not asked for again within the backoff' do
      with_cache
      token_for(orders_api)

      expect(token_for(orders_api)).to be_nil
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'logs once that the lifetime is unusable, naming the issuer and the audience' do
      with_cache

      token_for(orders_api)

      expect(log_lines.string.lines).to contain_exactly(
        a_string_including("Could not fetch a machine token for #{orders_api} from #{auth0_issuer}: #{unusable_lifetime}")
      )
    end
  end

  describe 'after a failure' do
    before { with_cache }

    it 'does not ask again within the backoff, and answers nil' do
      stub_request(:post, auth0_token_url).to_return(status: 503)
      token_for(orders_api)

      expect(token_for(orders_api)).to be_nil
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'asks again once the backoff has passed, and not before' do
      stub_request(:post, auth0_token_url).to_return({ status: 503 }, { status: 200, body: token_body })
      token_for(orders_api)

      Timecop.travel(Time.now + 9.seconds)
      expect(token_for(orders_api)).to be_nil
      Timecop.travel(Time.now + 2.seconds)
      expect(token_for(orders_api)).to include(token: 'auth0-token')
    end

    it 'is held back by a failure another process recorded in the cache' do
      stub_request(:post, auth0_token_url).to_return(status: 503)
      token_for(orders_api)
      service.send(:forget_process_markers)

      expect(token_for(orders_api)).to be_nil
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'still holds this process back when the cache keeps nothing' do
      with_a_cache_that_keeps_nothing
      stub_request(:post, auth0_token_url).to_return({ status: 503 }, { status: 200, body: token_body })
      token_for(orders_api)

      Timecop.travel(Time.now + 9.seconds)
      expect(token_for(orders_api)).to be_nil
      Timecop.travel(Time.now + 2.seconds)
      expect(token_for(orders_api)).to include(token: 'auth0-token')
    end

    it 'holds back only the audience that failed' do
      stub_request(:post, auth0_token_url).with(body: hash_including(audience: orders_api)).to_return(status: 503)
      stub_request(:post, auth0_token_url).with(body: hash_including(audience: billing_api)).to_return(status: 200, body: token_body)
      token_for(orders_api)

      expect(token_for(billing_api)).to include(token: 'auth0-token')
    end

    it 'holds back neither the entry\'s own audience nor the primary issuer' do
      stub_request(:post, auth0_token_url).with(body: hash_including(audience: orders_api)).to_return(status: 503)
      stub_request(:post, auth0_token_url).with(body: hash_including(audience: auth0_entry[:audience])).to_return(status: 200, body: token_body)
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))
      token_for(orders_api)

      expect(service.access_token(auth0_issuer)).to include(token: 'auth0-token')
      expect(service.access_token).to include(token: 'primary-token')
    end

    it 'forgets the failure when the cache is cleared' do
      stub_request(:post, auth0_token_url).to_return({ status: 503 }, { status: 200, body: token_body })
      token_for(orders_api)

      service.clear

      expect(token_for(orders_api)).to include(token: 'auth0-token')
    end
  end

  # Callers that miss the cache at the same moment wait for one fetch rather than each making their
  # own. The first caller is held inside the token endpoint until the second is seen to be waiting,
  # so the second really does arrive while the first fetch is in flight.
  describe 'concurrent callers in one process' do
    let(:arrived) { Queue.new }
    let(:release) { Queue.new }

    before { with_cache }

    after { 4.times { release << :go } }

    def hold_token_endpoint(status = 200)
      stub_request(:post, auth0_token_url).to_return do |request|
        arrived << URI.decode_www_form(request.body).to_h.fetch('audience')
        release.pop
        { status:, body: token_body }
      end
    end

    def wait_until_waiting(thread)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
      sleep 0.01 until thread.status == 'sleep' || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    end

    def concurrent_pair(first_audience, second_audience)
      first = Thread.new { token_for(first_audience) }
      arrived.pop(timeout: 2)
      second = Thread.new { token_for(second_audience) }
      wait_until_waiting(second)
      [first, second]
    end

    it 'makes one request for the same audience, and gives both callers its token' do
      hold_token_endpoint
      threads = concurrent_pair(orders_api, orders_api)

      2.times { release << :go }

      expect(threads.map { |thread| thread.value&.fetch(:token) }).to eq(%w[auth0-token auth0-token])
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'gives a caller that waited on a failed fetch nil, without a request of its own' do
      hold_token_endpoint(503)
      threads = concurrent_pair(orders_api, orders_api)

      2.times { release << :go }

      expect(threads.map(&:value)).to eq([nil, nil])
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'gives a caller that waited on a failed fetch nil, without a request of its own, when the cache keeps nothing' do
      with_a_cache_that_keeps_nothing
      hold_token_endpoint(503)
      threads = concurrent_pair(orders_api, orders_api)

      2.times { release << :go }

      expect(threads.map(&:value)).to eq([nil, nil])
      expect(requests_for(orders_api)).to have_been_made.once
    end

    it 'does not make a caller for another audience wait' do
      hold_token_endpoint
      first, second = concurrent_pair(orders_api, billing_api)

      expect(arrived.pop(timeout: 2)).to eq(billing_api)
      2.times { release << :go }
      expect([first, second].map { |thread| thread.value&.fetch(:token) }).to eq(%w[auth0-token auth0-token])
    end
  end

  describe 'without a cache' do
    it 'asks again on every call, exactly as before' do
      stub_request(:post, auth0_token_url).to_return(status: 503)

      2.times { token_for(orders_api) }

      expect(requests_for(orders_api)).to have_been_made.twice
    end
  end
end
