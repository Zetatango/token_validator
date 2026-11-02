# frozen_string_literal: true

require 'spec_helper'

# A caller that talks to several services needs a separate machine token for each, because each
# service accepts only tokens naming its own API. These examples cover asking an additional issuer
# for a token by audience, and the audiences that must be refused without asking anyone.
module TokenValidatorAudienceSpec
  Application = Class.new
end

RSpec.describe TokenValidator::OauthTokenService do
  subject(:service) { described_class.instance }

  def primary_issuer = 'https://idp.example.com/'
  def primary_token_url = 'https://idp.example.com//oauth/token'
  def auth0_issuer = 'https://tenant.ca.auth0.com/'
  def auth0_token_url = 'https://tenant.ca.auth0.com/oauth/token'
  def entry_audience = 'https://api.example.com/platform'
  def orders_api = 'https://api.example.com/orders'
  def billing_api = 'https://api.example.com/billing'

  def auth0_entry
    { issuer_url: auth0_issuer, jwks_url: "#{auth0_issuer}.well-known/jwks.json", audience: entry_audience,
      algorithm: 'RS256', client_id: 'auth0-client', client_secret: 'auth0-secret' }
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  def with_cache
    allow(Rails).to receive_messages(cache:, application: TokenValidatorAudienceSpec::Application.new)
  end

  # Answers a different token for each audience asked for, so a token handed to the wrong caller
  # shows up as the wrong value rather than as a correct-looking one.
  def stub_token_endpoint
    stub_request(:post, auth0_token_url).to_return do |request|
      audience = URI.decode_www_form(request.body).to_h.fetch('audience')
      { status: 200, body: { access_token: "token-for-#{audience}", expires_in: 86_400 }.to_json }
    end
  end

  def token_for(audience)
    service.access_token(auth0_issuer, audience:)&.fetch(:token)
  end

  def entry_audience_token
    service.access_token(auth0_issuer)&.fetch(:token)
  end

  before do
    TokenValidator::ValidatorConfig.configure(
      issuer_url: primary_issuer, client_id: 'primary-client', client_secret: 'primary-secret',
      requested_scope: 'test:scope', audience: 'https://primary.example.com'
    )
    TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry]
    service.instance_variable_set(:@access_token, nil)
  end

  describe 'asking an additional issuer for a token by audience' do
    before { stub_token_endpoint }

    it 'sends that audience in place of the entry\'s, with the same credentials and no scope' do
      service.access_token(auth0_issuer, audience: orders_api)

      expect(
        a_request(:post, auth0_token_url).with(
          body: { grant_type: 'client_credentials', client_id: 'auth0-client', client_secret: 'auth0-secret', audience: orders_api }
        )
      ).to have_been_made.once
    end

    it 'answers the token minted for that audience' do
      expect(token_for(orders_api)).to eq("token-for-#{orders_api}")
    end

    it 'builds a bearer header from it' do
      expect(service.oauth_auth_header(auth0_issuer, audience: orders_api)).to eq(authorization: "Bearer token-for-#{orders_api}")
    end

    it 'leaves the primary issuer\'s scratch slot alone' do
      service.access_token(auth0_issuer, audience: orders_api)

      expect(service.instance_variable_get(:@access_token)).to be_nil
    end
  end

  describe 'holding one token per audience' do
    before do
      with_cache
      stub_token_endpoint
    end

    it 'never hands one audience\'s token to a caller asking for another' do
      2.times do
        expect(token_for(orders_api)).to eq("token-for-#{orders_api}")
        expect(token_for(billing_api)).to eq("token-for-#{billing_api}")
        expect(entry_audience_token).to eq("token-for-#{entry_audience}")
      end
    end

    it 'fetches each audience once, and serves it from the cache after that' do
      3.times { [orders_api, billing_api].each { |audience| token_for(audience) } }

      expect(a_request(:post, auth0_token_url).with(body: hash_including(audience: orders_api))).to have_been_made.once
      expect(a_request(:post, auth0_token_url).with(body: hash_including(audience: billing_api))).to have_been_made.once
    end

    it 'caches it under the issuer and the audience, three minutes short of its lifetime' do
      allow(cache).to receive(:write).and_call_original

      token_for(orders_api)

      key = "access-token-#{Digest::SHA256.hexdigest(auth0_issuer)}-#{Digest::SHA256.hexdigest(orders_api)}"
      expect(cache).to have_received(:write).with(key, hash_including(token: "token-for-#{orders_api}"), hash_including(expires_in: 86_220))
    end

    it 'keeps an audience\'s key apart from the entry\'s own token and from the signing keys' do
      keys = [service.send(:access_token_cache_key, auth0_issuer, orders_api), service.send(:access_token_cache_key, auth0_issuer),
              service.send(:access_token_cache_key, auth0_issuer, billing_api), service.send(:jwks_cache_key, auth0_issuer)]

      expect(keys.uniq.size).to eq(4)
    end
  end

  describe 'when the token endpoint fails' do
    [[:to_return, { status: 401 }], [:to_raise, Errno::ECONNREFUSED]].each do |how, what|
      it "answers nil and an empty header (#{how} #{what})" do
        stub_request(:post, auth0_token_url).public_send(how, what)

        expect(token_for(orders_api)).to be_nil
        expect(service.oauth_auth_header(auth0_issuer, audience: orders_api)).to eq({})
      end
    end
  end

  # Each of these asks for an audience the library cannot honour. Answering with a token for some
  # other API would let a caller send a token the receiving service never agreed to, so the answer
  # is nothing, and nothing is requested.
  describe 'an audience that cannot be honoured' do
    [nil, '', '   ', :orders, ['https://api.example.com/orders'], 42].each do |audience|
      it "refuses #{audience.inspect} without asking for a token" do
        expect(service.access_token(auth0_issuer, audience:)).to be_nil
        expect(service.oauth_auth_header(auth0_issuer, audience:)).to eq({})
        expect(a_request(:post, //)).not_to have_been_made
      end
    end

    it 'refuses any audience for the primary issuer, which is never sent one' do
      expect(service.access_token(audience: orders_api)).to be_nil
      expect(service.access_token(primary_issuer, audience: orders_api)).to be_nil
      expect(a_request(:post, primary_token_url)).not_to have_been_made
    end

    it 'refuses an audience for an issuer configured only for verification' do
      TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry.except(:client_id, :client_secret)]

      expect(service.access_token(auth0_issuer, audience: orders_api)).to be_nil
      expect(a_request(:post, //)).not_to have_been_made
    end

    it 'refuses an audience for an issuer this library does not trust' do
      expect(service.access_token('https://attacker.example.com/', audience: orders_api)).to be_nil
      expect(a_request(:post, //)).not_to have_been_made
    end
  end
end
