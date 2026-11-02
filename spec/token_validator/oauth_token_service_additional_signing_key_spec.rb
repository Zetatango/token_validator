# frozen_string_literal: true

require 'spec_helper'

# How an additional issuer's signing keys are fetched and kept: within explicit timeouts, refreshed
# hourly but kept through a failed refresh for up to a day, held back after a failure, refetched for
# an unknown key id at most once a minute, and replaced only by a fetch that succeeded.
module TokenValidatorSigningKeySpec
  Application = Class.new
  KEYS = Hash.new { |keys, kid| keys[kid] = OpenSSL::PKey::RSA.new(2048) }
end

RSpec.describe TokenValidator::OauthTokenService do
  subject(:service) { described_class.instance }

  def primary_issuer = 'https://idp.example.com/'
  def primary_jwks_url = 'https://idp.example.com//oauth/discovery/keys'
  def auth0_issuer = 'https://tenant.ca.auth0.com/'
  def auth0_jwks_url = 'https://tenant.ca.auth0.com/.well-known/jwks.json'
  def other_issuer = 'https://other.example.com/'
  def other_jwks_url = 'https://other.example.com/.well-known/jwks.json'

  def entry_for(issuer_url, jwks_url)
    { issuer_url:, jwks_url:, audience: 'https://api.example.com', algorithm: 'RS256' }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def with_cache
    allow(Rails).to receive_messages(cache:, application: TokenValidatorSigningKeySpec::Application.new)
  end

  def jwk(kid)
    TokenValidatorSigningKeySpec::KEYS[kid].public_key.to_jwk(kid:, use: 'sig', alg: 'RS256')
  end

  def key_set(*kids)
    { status: 200, body: { keys: kids.map { |kid| jwk(kid) } }.to_json }
  end

  def kids(key_set)
    key_set&.map { |key| key['kid'] }
  end

  def log_lines
    @log_lines ||= StringIO.new
  end

  before do
    TokenValidator::ValidatorConfig.configure(issuer_url: primary_issuer, audience: 'https://primary.example.com')
    TokenValidator::ValidatorConfig.additional_issuers = [entry_for(auth0_issuer, auth0_jwks_url), entry_for(other_issuer, other_jwks_url)]
    allow(TokenValidator::ValidatorConfig).to receive(:logger).and_return(Logger.new(log_lines))
  end

  after do
    Timecop.return
    TokenValidator::ValidatorConfig.additional_issuers = []
  end

  it 'gives the HTTP client explicit open and read timeouts' do
    allow(RestClient::Request).to receive(:execute).and_call_original
    stub_request(:get, auth0_jwks_url).to_return(key_set('a'))

    service.signing_key(auth0_issuer)

    expect(RestClient::Request).to have_received(:execute).with(hash_including(method: :get, open_timeout: 5, read_timeout: 10))
  end

  # Each of these used to raise out of the fetch. Now each answers no keys, so a token naming the
  # issuer is refused rather than turned into a server error.
  describe 'a key set that cannot be fetched or used' do
    {
      'a DNS failure' => ->(stub) { stub.to_raise(SocketError) },
      'a connection reset' => ->(stub) { stub.to_raise(Errno::ECONNRESET) },
      'a TLS failure' => ->(stub) { stub.to_raise(OpenSSL::SSL::SSLError) },
      'a broken stream' => ->(stub) { stub.to_raise(IOError) },
      'a timeout' => lambda(&:to_timeout),
      'a server error' => ->(stub) { stub.to_return(status: 500) },
      'a body that is not JSON' => ->(stub) { stub.to_return(status: 200, body: '<html>maintenance</html>') },
      'a body that is a JSON list' => ->(stub) { stub.to_return(status: 200, body: '[]') },
      'a body that is JSON null' => ->(stub) { stub.to_return(status: 200, body: 'null') },
      'a body with no keys' => ->(stub) { stub.to_return(status: 200, body: '{}') },
      'keys that are not a list' => ->(stub) { stub.to_return(status: 200, body: '{"keys":"none"}') },
      'an empty list of keys' => ->(stub) { stub.to_return(status: 200, body: '{"keys":[]}') },
      'keys that are not objects' => ->(stub) { stub.to_return(status: 200, body: '{"keys":[1,"two",null]}') },
      'keys none of which can verify' => ->(stub) { stub.to_return(status: 200, body: '{"keys":[{"kty":"RSA","kid":"k"},{"kid":"j"}]}') }
    }.each do |failure, respond|
      it "answers no keys for #{failure}, with or without a cache" do
        instance_exec(stub_request(:get, auth0_jwks_url), &respond)

        expect(service.signing_key(auth0_issuer)).to be_nil
        with_cache
        expect(service.signing_key(auth0_issuer)).to be_nil
      end
    end

    it 'logs the issuer and the kind of failure, never the body' do
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: 'not json: auth0-secret')

      service.signing_key(auth0_issuer)

      expect(log_lines.string).to include("Could not fetch signing keys from #{auth0_issuer}: JSON::ParserError")
      expect(log_lines.string).not_to include('auth0-secret')
    end

    # One of each way json-jwt was seen to fail converting a published key.
    {
      'missing its modulus' => { kty: 'RSA', kid: 'x', e: 'AQAB' },
      'whose modulus is not a string' => { kty: 'RSA', kid: 'x', n: 5, e: 'AQAB' },
      'whose modulus is not base64' => { kty: 'RSA', kid: 'x', n: '!!!', e: 'AQAB' },
      'of no known type' => { kid: 'x' },
      'whose point is not on its curve' => { kty: 'EC', kid: 'x', crv: 'P-256', x: 'AA', y: 'AA' }
    }.each do |shape, unusable_key|
      it "leaves out a key #{shape}, and keeps the rest" do
        stub_request(:get, auth0_jwks_url).to_return(status: 200, body: { keys: [unusable_key, jwk('a')] }.to_json)

        expect(kids(service.signing_key(auth0_issuer))).to eq(['a'])
      end
    end

    it 'keeps the usable keys of a set that also holds unusable ones, and says how many it left out' do
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: { keys: [jwk('a'), { kty: 'RSA', kid: 'b' }, 7] }.to_json)

      expect(kids(service.signing_key(auth0_issuer))).to eq(['a'])
      expect(log_lines.string).to include("Ignored 2 unusable signing key(s) from #{auth0_issuer}")
    end
  end

  describe 'with a cache' do
    before { with_cache }

    it 'keeps the set where earlier releases look for it, as the same kind of object' do
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'))

      service.signing_key(auth0_issuer)

      expect(cache.read("issuer-jwks-#{Digest::SHA256.hexdigest(auth0_issuer)}", namespace: service.send(:namespace)))
        .to be_a(JSON::JWK::Set)
    end

    it 'caches the set for a day, and counts it fresh for an hour' do
      allow(cache).to receive(:write).and_call_original
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'))

      service.signing_key(auth0_issuer)

      expect(cache).to have_received(:write).with(/\Aissuer-jwks-\h+\z/, anything, hash_including(expires_in: 24.hours))
      expect(cache).to have_received(:write).with(/\Aissuer-jwks-fresh-\h+\z/, true, hash_including(expires_in: 1.hour))
    end

    it 'serves a fresh set without fetching it again' do
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'))
      service.signing_key(auth0_issuer)

      Timecop.travel(Time.now + 59.minutes) { service.signing_key(auth0_issuer) }

      expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
    end

    it 'fetches the set again once it is an hour old, and uses what it gets' do
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'), key_set('b'))
      service.signing_key(auth0_issuer)

      Timecop.travel(Time.now + 61.minutes)

      expect(kids(service.signing_key(auth0_issuer))).to eq(['b'])
    end

    it 'keeps using the old set when that refresh fails, and does not retry within the backoff' do
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'), { status: 503 })
      service.signing_key(auth0_issuer)

      Timecop.travel(Time.now + 61.minutes)

      expect(Array.new(2) { kids(service.signing_key(auth0_issuer)) }).to eq([['a'], ['a']])
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
    end

    it 'stops trusting the old set once it is a day old' do
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'), { status: 503 })
      service.signing_key(auth0_issuer)

      Timecop.travel(Time.now + 24.hours + 1.minute)

      expect(service.signing_key(auth0_issuer)).to be_nil
    end

    it 'does not ask again within the backoff after a failed fetch, and asks once it has passed' do
      stub_request(:get, auth0_jwks_url).to_return({ status: 503 }, key_set('a'))
      service.signing_key(auth0_issuer)

      expect(service.signing_key(auth0_issuer)).to be_nil
      Timecop.travel(Time.now + 11.seconds)
      expect(kids(service.signing_key(auth0_issuer))).to eq(['a'])
    end

    it 'forgets a failure when the cache is cleared' do
      stub_request(:get, auth0_jwks_url).to_return({ status: 503 }, key_set('a'))
      service.signing_key(auth0_issuer)

      service.clear

      expect(kids(service.signing_key(auth0_issuer))).to eq(['a'])
    end
  end

  # Called for a token naming a key id the cached set lacks: a rotation in the normal case, and an
  # unauthenticated stranger's token in the bad one.
  describe 'refetching for an unknown key id' do
    before do
      with_cache
      stub_request(:get, auth0_jwks_url).to_return(key_set('a'), key_set('a', 'b'))
      service.signing_key(auth0_issuer)
    end

    it 'fetches again and answers the new set' do
      expect(kids(service.refetch_signing_key(auth0_issuer))).to eq(%w[a b])
      expect(kids(service.signing_key(auth0_issuer))).to eq(%w[a b])
    end

    it 'fetches at most once a minute, answering the cached set in between' do
      service.refetch_signing_key(auth0_issuer)

      expect(kids(service.refetch_signing_key(auth0_issuer))).to eq(%w[a b])
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
    end

    it 'may fetch again once the minute has passed' do
      service.refetch_signing_key(auth0_issuer)

      Timecop.travel(Time.now + 61.seconds) { service.refetch_signing_key(auth0_issuer) }

      expect(a_request(:get, auth0_jwks_url)).to have_been_made.times(3)
    end

    it 'counts the minute per issuer' do
      stub_request(:get, other_jwks_url).to_return(key_set('c'))
      service.refetch_signing_key(auth0_issuer)

      expect(kids(service.refetch_signing_key(other_issuer))).to eq(['c'])
    end

    it 'keeps the cached set when the refetch fails' do
      stub_request(:get, auth0_jwks_url).to_return(status: 503)

      expect(service.refetch_signing_key(auth0_issuer)).to be_nil
      expect(kids(service.signing_key(auth0_issuer))).to eq(['a'])
    end

    it 'does not fetch when the cache cannot record the refetch' do
      allow(cache).to receive(:write).and_call_original
      allow(cache).to receive(:write).with(anything, anything, hash_including(unless_exist: true)).and_return(false)

      expect(kids(service.refetch_signing_key(auth0_issuer))).to eq(['a'])
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
    end
  end

  it 'refetches nothing for an issuer this library does not trust' do
    expect(service.refetch_signing_key('https://attacker.example.com/')).to be_nil
    expect(a_request(:get, //)).not_to have_been_made
  end

  it 'refetches the primary issuer\'s keys every time it is asked, as it always has' do
    with_cache
    stub_request(:get, primary_jwks_url).to_return(key_set('primary'))

    2.times { service.refetch_signing_key }

    expect(a_request(:get, primary_jwks_url)).to have_been_made.twice
  end

  # The first caller is held inside the key endpoint until the second is seen to be waiting (or has
  # come back), so the second really does arrive while the first fetch is in flight.
  describe 'concurrent callers in one process' do
    let(:arrived) { Queue.new }
    let(:release) { Queue.new }

    before { with_cache }

    after { 4.times { release << :go } }

    def hold_key_endpoint(*responses)
      stub_request(:get, auth0_jwks_url).to_return do
        arrived << :fetching
        release.pop
        responses.shift
      end
    end

    # Until the thread is blocked or has finished. Thread#status is "sleep" or false respectively.
    def settle(thread)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
      sleep 0.01 until thread.status == 'sleep' || thread.status == false || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    end

    def while_one_fetch_is_in_flight
      first = Thread.new { service.signing_key(auth0_issuer) }
      arrived.pop
      second = Thread.new { service.signing_key(auth0_issuer) }
      settle(second)
      [first, second]
    end

    it 'fetches an uncached set once, for both callers' do
      hold_key_endpoint(key_set('a'), key_set('a'))
      threads = while_one_fetch_is_in_flight

      2.times { release << :go }

      expect(threads.map { |thread| kids(thread.value) }).to eq([['a'], ['a']])
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
    end

    it 'lets other callers carry on with a stale set while one refreshes it' do
      hold_key_endpoint(key_set('a'), key_set('b'))
      release << :go
      service.signing_key(auth0_issuer)
      arrived.pop
      Timecop.travel(Time.now + 61.minutes)

      first, second = while_one_fetch_is_in_flight

      expect(kids(second.join(2)&.value)).to eq(['a'])
      release << :go
      expect(kids(first.value)).to eq(['b'])
    end
  end
end
