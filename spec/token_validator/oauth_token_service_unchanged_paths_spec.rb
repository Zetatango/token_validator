# frozen_string_literal: true

require 'spec_helper'

# Behaviour that must survive this library's per-audience machine tokens and its hardened fetching
# untouched, pinned against the code as it stood before either existed.
#
# Two paths are covered. The primary issuer keeps every part of its behaviour, failures included:
# the client library's default timeouts, the exceptions it has always let escape, no backoff after a
# failure, no limit on refetching keys and no expiry on cached keys. An additional issuer asked for a
# machine token *without* an audience keeps the request it sends, the cache entry it writes and the
# nil it answers on failure.
module TokenValidatorUnchangedPathsSpec
  Application = Class.new
  SIGNING_KEY = OpenSSL::PKey::RSA.new(2048)
end

RSpec.describe TokenValidator::OauthTokenService do
  subject(:service) { described_class.instance }

  def primary_issuer = 'https://idp.example.com/'
  def primary_token_url = 'https://idp.example.com//oauth/token'
  def primary_jwks_url = 'https://idp.example.com//oauth/discovery/keys'
  def auth0_issuer = 'https://tenant.ca.auth0.com/'
  def auth0_token_url = 'https://tenant.ca.auth0.com/oauth/token'
  def signing_key = TokenValidatorUnchangedPathsSpec::SIGNING_KEY

  def auth0_entry
    { issuer_url: auth0_issuer, jwks_url: "#{auth0_issuer}.well-known/jwks.json", audience: 'https://api.example.com',
      algorithm: 'RS256', client_id: 'auth0-client', client_secret: 'auth0-secret' }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def with_cache
    allow(Rails).to receive_messages(cache:, application: TokenValidatorUnchangedPathsSpec::Application.new)
  end

  def token_body(value, expires_in = 3600)
    { access_token: value, expires_in: }.to_json
  end

  def stub_primary_jwks
    body = { keys: [signing_key.public_key.to_jwk(kid: 'primary-kid', use: 'sig', alg: 'RS512')] }.to_json
    stub_request(:get, primary_jwks_url).to_return(status: 200, body:)
  end

  def primary_token(kid: 'primary-kid')
    claims = { sub: 'subject', iat: Time.now.to_i, exp: (Time.now + 30.minutes).to_i, iss: primary_issuer,
               aud: 'https://primary.example.com', scopes: ['test:api'], kid: }
    JWT.encode(claims, signing_key, 'RS512')
  end

  def validates?(token)
    TokenValidator::TokenService.new(token, ['test:api']).valid_access_token?
  end

  def digest(value) = Digest::SHA256.hexdigest(value)

  before do
    TokenValidator::ValidatorConfig.configure(
      issuer_url: primary_issuer, client_id: 'primary-client', client_secret: 'primary-secret',
      requested_scope: 'test:scope', audience: 'https://primary.example.com'
    )
    TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry]
    service.instance_variable_set(:@access_token, nil)
  end

  after { Timecop.return }

  describe 'the primary issuer\'s machine token' do
    it 'answers exactly the token, its expiry time and its lifetime' do
      Timecop.freeze(Time.at(1_800_000_000))
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))

      expect(service.access_token).to eq(token: 'primary-token', expires: 1_800_003_600, expires_in: 3600)
    end

    it 'caches under the key it has always used, three minutes short of the token\'s lifetime' do
      with_cache
      allow(cache).to receive(:write).and_call_original
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))

      service.access_token

      expect(cache).to have_received(:write)
        .with("access-token-#{digest(primary_issuer)}", hash_including(token: 'primary-token'), hash_including(expires_in: 3420))
    end

    it 'keeps the token in the scratch slot only the primary issuer uses' do
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))

      service.access_token

      expect(service.instance_variable_get(:@access_token)).to include(token: 'primary-token')
    end

    it 'passes the client library no timeouts, so its defaults still apply' do
      allow(RestClient::Request).to receive(:execute).and_call_original
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))

      service.access_token

      expect(RestClient::Request).to have_received(:execute).with(hash_excluding(:timeout, :open_timeout, :read_timeout))
    end

    it 'still lets a DNS failure escape, as it always has' do
      stub_request(:post, primary_token_url).to_raise(SocketError)

      expect { service.access_token }.to raise_error(SocketError)
    end

    it 'tries again on the very next call after a failure' do
      with_cache
      stub_request(:post, primary_token_url).to_return(status: 503)

      2.times { service.access_token }

      expect(a_request(:post, primary_token_url)).to have_been_made.twice
    end
  end

  describe 'the primary issuer\'s signing keys' do
    it 'caches them under the key it has always used' do
      with_cache
      stub_primary_jwks

      service.signing_key

      expect(cache.read("issuer-jwks-#{digest(primary_issuer)}", namespace: service.send(:namespace))).to be_present
    end

    it 'passes the client library no timeouts' do
      allow(RestClient::Request).to receive(:execute).and_call_original
      stub_primary_jwks

      service.signing_key

      expect(RestClient::Request).to have_received(:execute).with(hash_excluding(:timeout, :open_timeout, :read_timeout))
    end

    it 'still lets a DNS failure escape verification, as it always has' do
      stub_request(:get, primary_jwks_url).to_raise(SocketError)

      expect { validates?(primary_token) }.to raise_error(SocketError)
    end

    it 'never expires them' do
      with_cache
      stub_primary_jwks
      service.signing_key

      Timecop.travel(Time.now + 30.days) { service.signing_key }

      expect(a_request(:get, primary_jwks_url)).to have_been_made.once
    end

    it 'refetches them for every token naming a kid it has not seen' do
      with_cache
      stub_primary_jwks

      3.times { validates?(primary_token(kid: 'no-such-kid')) }

      expect(a_request(:get, primary_jwks_url)).to have_been_made.times(4)
    end
  end

  describe 'an additional issuer\'s machine token, asked for without an audience' do
    it 'posts exactly the client credentials and the entry\'s audience, and no scope' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      service.access_token(auth0_issuer)

      expect(
        a_request(:post, auth0_token_url).with(
          body: { grant_type: 'client_credentials', client_id: 'auth0-client', client_secret: 'auth0-secret',
                  audience: 'https://api.example.com' }
        )
      ).to have_been_made.once
    end

    it 'answers exactly the token, its expiry time and its lifetime' do
      Timecop.freeze(Time.at(1_800_000_000))
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token', 86_400))

      expect(service.access_token(auth0_issuer)).to eq(token: 'auth0-token', expires: 1_800_086_400, expires_in: 86_400)
    end

    it 'caches under the key it has always used, three minutes short of the token\'s lifetime' do
      with_cache
      allow(cache).to receive(:write).and_call_original
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token', 86_400))

      service.access_token(auth0_issuer)

      expect(cache).to have_received(:write)
        .with("access-token-#{digest(auth0_issuer)}", hash_including(token: 'auth0-token'), hash_including(expires_in: 86_220))
    end

    it 'leaves the primary issuer\'s scratch slot alone' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      service.access_token(auth0_issuer)

      expect(service.instance_variable_get(:@access_token)).to be_nil
    end

    [[:to_return, { status: 401 }], [:to_return, { status: 500 }], [:to_raise, Errno::ECONNREFUSED]].each do |how, what|
      it "answers nil, and an empty header, when the token endpoint #{how == :to_raise ? 'refuses the connection' : "returns #{what[:status]}"}" do
        stub_request(:post, auth0_token_url).public_send(how, what)

        expect(service.access_token(auth0_issuer)).to be_nil
        expect(service.oauth_auth_header(auth0_issuer)).to eq({})
      end
    end
  end
end
