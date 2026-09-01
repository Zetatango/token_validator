# frozen_string_literal: true

require 'spec_helper'

# See the signing-key spec for why this stand-in exists: the cache namespace is derived from
# Rails.application's module name, which does not exist in this suite.
module TokenValidatorMachineTokenSpec
  Application = Class.new
end

RSpec.describe TokenValidator::OauthTokenService do
  subject(:service) { described_class.instance }

  let(:primary_issuer) { 'https://idp.example.com' }
  let(:primary_token_url) { "#{primary_issuer}/oauth/token" }
  let(:auth0_issuer) { 'https://tenant.ca.auth0.com/' }
  let(:auth0_token_url) { 'https://tenant.ca.auth0.com/oauth/token' }

  let(:auth0_entry) do
    {
      issuer_url: auth0_issuer,
      jwks_url: "#{auth0_issuer}.well-known/jwks.json",
      audience: 'https://api.example.com',
      algorithm: 'RS256',
      client_id: 'auth0-client',
      client_secret: 'auth0-secret'
    }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def with_cache
    allow(Rails).to receive_messages(
      cache: cache,
      application: TokenValidatorMachineTokenSpec::Application.new
    )
  end

  def token_body(value)
    { access_token: value, expires_in: 3600 }.to_json
  end

  before do
    TokenValidator::ValidatorConfig.configure(
      issuer_url: primary_issuer,
      client_id: 'primary-client',
      client_secret: 'primary-secret',
      requested_scope: 'test:scope',
      audience: 'https://primary.example.com'
    )
    TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry]
    service.instance_variable_set(:@access_token, nil)
  end

  describe 'what gets sent, per issuer (TKV.17)' do
    it 'sends the primary issuer exactly what it has always sent' do
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))

      service.access_token

      expect(
        a_request(:post, primary_token_url).with(
          body: { grant_type: 'client_credentials', client_id: 'primary-client',
                  client_secret: 'primary-secret', scope: 'test:scope' }
        )
      ).to have_been_made
    end

    it 'includes audience for an Auth0 issuer' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      service.access_token(auth0_issuer)

      expect(
        a_request(:post, auth0_token_url).with(body: hash_including(audience: 'https://api.example.com'))
      ).to have_been_made
    end

    # The primary provider's endpoint rejects an unexpected parameter, and sending an audience it
    # never asked for is a behaviour change to a path that must not change at all.
    it 'never sends audience to the primary issuer' do
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))

      service.access_token

      expect(
        a_request(:post, primary_token_url).with { |req| req.body.include?('audience') }
      ).not_to have_been_made
    end

    it 'uses the entry\'s own credentials, not the primary issuer\'s' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      service.access_token(auth0_issuer)

      expect(
        a_request(:post, auth0_token_url)
          .with(body: hash_including(client_id: 'auth0-client', client_secret: 'auth0-secret'))
      ).to have_been_made
    end

    it 'honours an explicit token_url over the derived one' do
      TokenValidator::ValidatorConfig.additional_issuers =
        [auth0_entry.merge(token_url: 'https://login.example.com/oauth/token')]
      stub_request(:post, 'https://login.example.com/oauth/token')
        .to_return(status: 200, body: token_body('auth0-token'))

      service.access_token(auth0_issuer)

      expect(a_request(:post, 'https://login.example.com/oauth/token')).to have_been_made
    end

    # The primary issuer ends in a slash in every environment, so its token endpoint has always
    # carried a double slash. Pinned for the same reason the JWKS address is.
    it 'keeps the double slash the primary issuer has always produced' do
      TokenValidator::ValidatorConfig.configure(issuer_url: 'https://idp.example.com/')
      doubled = 'https://idp.example.com//oauth/token'
      stub_request(:post, doubled).to_return(status: 200, body: token_body('primary-token'))

      service.access_token

      expect(a_request(:post, doubled)).to have_been_made
    end
  end

  describe 'refusing to mint a token it has no right to' do
    it 'returns nothing for an issuer configured only for verification' do
      TokenValidator::ValidatorConfig.additional_issuers =
        [auth0_entry.except(:client_id, :client_secret)]

      expect(service.access_token(auth0_issuer)).to be_nil
      expect(a_request(:post, //)).not_to have_been_made
    end

    it 'never posts the primary issuer\'s secret to another issuer\'s endpoint' do
      TokenValidator::ValidatorConfig.additional_issuers =
        [auth0_entry.except(:client_id, :client_secret)]

      service.access_token(auth0_issuer)

      expect(a_request(:post, //).with { |req| req.body.include?('primary-secret') }).not_to have_been_made
    end

    it 'returns nothing for an issuer this library does not trust' do
      expect(service.access_token('https://attacker.example.com/')).to be_nil
      expect(a_request(:post, //)).not_to have_been_made
    end

    # Same rule as the signing keys: only an omitted argument means the primary issuer.
    ['', '   '].each do |blank_issuer|
      it "refuses a blank issuer #{blank_issuer.inspect}" do
        expect(service.access_token(blank_issuer)).to be_nil
        expect(a_request(:post, //)).not_to have_been_made
      end
    end
  end

  describe 'keeping one issuer\'s tokens away from another (TKV.17)' do
    before { with_cache }

    it 'never returns the token cached for one issuer when asked for another' do
      stub_request(:post, primary_token_url).to_return(status: 200, body: token_body('primary-token'))
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      expect(service.access_token[:token]).to eq('primary-token')
      expect(service.access_token(auth0_issuer)[:token]).to eq('auth0-token')
      expect(service.access_token(auth0_issuer)[:token]).to eq('auth0-token')
      expect(service.access_token[:token]).to eq('primary-token')
    end

    it 'gives each issuer its own cache key' do
      expect(service.send(:access_token_cache_key, primary_issuer))
        .not_to eq(service.send(:access_token_cache_key, auth0_issuer))
    end

    # The signing keys and the machine tokens are different things about the same issuer, so they
    # must not collide in the cache either.
    it 'does not collide with the signing-key entry for the same issuer' do
      expect(service.send(:access_token_cache_key, auth0_issuer))
        .not_to eq(service.send(:jwks_cache_key, auth0_issuer))
    end

    it 'serves a second request for the same issuer from the cache' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      3.times { service.access_token(auth0_issuer) }

      expect(a_request(:post, auth0_token_url)).to have_been_made.once
    end

    it 'expires a cached token early, as it always has' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))
      allow(cache).to receive(:write).and_call_original

      service.access_token(auth0_issuer)

      expect(cache).to have_received(:write).with(anything, anything, hash_including(expires_in: 3600 - 180))
    end
  end

  describe 'the header helpers' do
    it 'builds a bearer header for an additional issuer' do
      stub_request(:post, auth0_token_url).to_return(status: 200, body: token_body('auth0-token'))

      expect(service.oauth_auth_header(auth0_issuer)).to eq(authorization: 'Bearer auth0-token')
    end

    it 'returns an empty header when no token can be obtained' do
      expect(service.oauth_auth_header('https://attacker.example.com/')).to eq({})
    end
  end
end
