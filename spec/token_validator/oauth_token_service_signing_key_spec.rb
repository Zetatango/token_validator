# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# The cache namespace is derived from Rails.application's module name, which does not exist in
# this suite. A named stand-in lets the real namespace code run rather than stubbing a method on
# the object under test.
module TokenValidatorCacheSpec
  Application = Class.new
end

RSpec.describe TokenValidator::OauthTokenService do
  subject(:service) { described_class.instance }

  # Written without a trailing slash so the expected addresses read plainly. The trailing-slash
  # case that production actually runs is pinned in its own example, further down.
  let(:primary_issuer) { 'https://idp.example.com' }
  let(:primary_jwks_url) { "#{primary_issuer}/oauth/discovery/keys" }
  let(:auth0_issuer) { 'https://tenant.ca.auth0.com/' }
  let(:auth0_jwks_url) { "#{auth0_issuer}.well-known/jwks.json" }

  let(:auth0_entry) do
    {
      issuer_url: auth0_issuer,
      jwks_url: auth0_jwks_url,
      audience: 'https://api.example.com',
      algorithm: 'RS256'
    }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def jwks_body(kid)
    key = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), { kid:, use: 'sig', alg: 'RS256' })
    { keys: [key.verify_key.to_jwk(kid:)] }.to_json
  end

  # Rails.cache is nil throughout this suite, which means the caching branch is never otherwise
  # exercised. Giving it a real store is the only way to test the isolation this issue is about.
  def with_cache
    allow(Rails).to receive_messages(
      cache: cache,
      application: TokenValidatorCacheSpec::Application.new
    )
  end

  def kid_of(key_set)
    key_set&.first&.[]('kid')
  end

  before do
    TokenValidator::ValidatorConfig.configure(
      issuer_url: primary_issuer,
      audience: 'https://primary.example.com'
    )
    TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry]
  end

  describe 'which address each issuer is fetched from (TKV.03)' do
    it 'fetches the primary issuer from the discovery path it has always used' do
      stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))

      service.signing_key

      expect(a_request(:get, primary_jwks_url)).to have_been_made
    end

    it 'fetches an additional issuer from the jwks_url its entry carries' do
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: jwks_body('auth0-kid'))

      service.signing_key(auth0_issuer)

      expect(a_request(:get, auth0_jwks_url)).to have_been_made
    end

    it 'does not fetch the primary address when asked for an additional issuer' do
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: jwks_body('auth0-kid'))
      stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))

      service.signing_key(auth0_issuer)

      expect(a_request(:get, primary_jwks_url)).not_to have_been_made
    end

    it 'asks for nothing at all when the issuer is not one this library trusts' do
      service.signing_key('https://attacker.example.com/')

      expect(a_request(:get, //)).not_to have_been_made
    end

    it 'returns nothing for an untrusted issuer, rather than falling back to the primary keys' do
      stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))

      expect(service.signing_key('https://attacker.example.com/')).to be_nil
    end

    # An empty issuer is a *named* issuer that happens to be blank, not "no issuer given".
    # ValidatorConfig rejects it deliberately, and this layer must not route around that guard by
    # treating blank as absent -- that would hand the primary issuer's keys to a token whose `iss`
    # claim is empty or missing.
    ['', '   '].each do |blank_issuer|
      it "refuses a blank issuer #{blank_issuer.inspect} rather than falling back to the primary" do
        stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))

        expect(service.signing_key(blank_issuer)).to be_nil
        expect(a_request(:get, primary_jwks_url)).not_to have_been_made
      end
    end

    # Only an omitted argument means "the primary issuer".
    it 'still treats an omitted issuer as the primary one' do
      stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))

      expect(kid_of(service.signing_key)).to eq('primary-kid')
    end

    # The configured primary issuer ends in a slash in every environment, so oauth_path has always
    # produced a double slash here. ValidatorConfig reproduces that deliberately; this pins that it
    # survives the move to jwks_url, because normalising it would silently move the address.
    it 'keeps the double slash a trailing-slash issuer has always produced' do
      TokenValidator::ValidatorConfig.configure(issuer_url: 'https://idp.example.com/')
      double_slashed = 'https://idp.example.com//oauth/discovery/keys'
      stub_request(:get, double_slashed).to_return(status: 200, body: jwks_body('primary-kid'))

      service.signing_key

      expect(a_request(:get, double_slashed)).to have_been_made
    end
  end

  describe 'keeping one issuer\'s keys away from another (TKV.04)' do
    before { with_cache }

    it 'never returns the keys cached for one issuer when asked for another' do
      stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: jwks_body('auth0-kid'))

      expect(kid_of(service.signing_key)).to eq('primary-kid')
      expect(kid_of(service.signing_key(auth0_issuer))).to eq('auth0-kid')
      # Asked again, in the other order, now that both are cached.
      expect(kid_of(service.signing_key(auth0_issuer))).to eq('auth0-kid')
      expect(kid_of(service.signing_key)).to eq('primary-kid')
    end

    it 'gives each issuer its own cache key' do
      primary_key = service.send(:jwks_cache_key, primary_issuer)
      auth0_key = service.send(:jwks_cache_key, auth0_issuer)

      expect(primary_key).not_to eq(auth0_key)
    end

    it 'serves a second request for the same issuer from the cache' do
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: jwks_body('auth0-kid'))

      3.times { service.signing_key(auth0_issuer) }

      expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
    end

    it 'clears every issuer, not just one' do
      stub_request(:get, primary_jwks_url).to_return(status: 200, body: jwks_body('primary-kid'))
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: jwks_body('auth0-kid'))
      service.signing_key
      service.signing_key(auth0_issuer)

      service.clear

      service.signing_key
      service.signing_key(auth0_issuer)
      expect(a_request(:get, primary_jwks_url)).to have_been_made.twice
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
    end
  end

  describe 'without a cache configured' do
    it 'still fetches each issuer from its own address' do
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body: jwks_body('auth0-kid'))

      expect(kid_of(service.signing_key(auth0_issuer))).to eq('auth0-kid')
    end

    it 'returns nothing when the issuer cannot be reached' do
      stub_request(:get, auth0_jwks_url).to_raise(Errno::ECONNREFUSED)

      expect(service.signing_key(auth0_issuer)).to be_nil
    end
  end

  describe 'when this library is not configured at all' do
    it 'trusts nothing rather than fetching from a half-built address' do
      TokenValidator::ValidatorConfig.configure(issuer_url: '', audience: '')
      TokenValidator::ValidatorConfig.additional_issuers = []

      expect(service.signing_key).to be_nil
      expect(a_request(:get, //)).not_to have_been_made
    end
  end
end
