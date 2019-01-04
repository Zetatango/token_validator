# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

RSpec.describe TokenValidator::TokenService, type: :request do
  let(:expected_scopes) do
    ['test:api']
  end

  let(:issuer_url) { 'https://localhost:3002' }
  let(:audience) { 'https://localhost:3000' }

  before do
    TokenValidator::ValidatorConfig.configure(issuer_url: issuer_url, audience: audience)

    TokenValidator::TokenService.clear
  end

  def stub_jwks_response
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_return(status: 200, body: verification_jwks.to_json)
  end

  def verification_jwks
    { keys: [JSON.parse(verification_key.to_binary)] }
  end

  def key_id
    @key_id ||= SecureRandom.uuid
  end

  def generate_key(kid = nil)
    jwk = JOSE::JWK.generate_key([:rsa, 4096])
    jwk.merge('kid' => kid.nil? ? key_id : kid,
              'use' => 'sig')
  end

  def current_key
    @current_key ||= generate_key
  end

  def signing_key
    current_key
  end

  def verification_key
    current_key.to_public
  end

  # rubocop:disable Metrics/CyclomaticComplexity
  # rubocop:disable Metrics/PerceivedComplexity
  def access_token(options = {})
    valid_signature = options.key?(:valid_signature) ? options[:valid_signature] : true
    issuer = options.key?(:issuer) ? options[:issuer] : issuer_url
    aud = options.key?(:audience) ? options[:audience] : ['https://localhost:3000']
    delete_keys = options.key?(:delete_keys) ? options[:delete_keys] : []
    partner_guid = options.key?(:partner_guid) ? options[:partner_guid] : "p_#{SecureRandom.base58(16)}"
    scopes = options.key?(:scopes) ? options[:scopes] : ['test:api']

    payload = {
      sub: SecureRandom.hex(64),
      iat: Time.now.to_i,
      exp: (Time.now + 30.minutes).to_i,
      jti: SecureRandom.uuid,
      kid: key_id,
      iss: issuer,
      aud: aud,
      partner_guid: partner_guid,
      scopes: scopes
    }

    payload[:merchant_guid] = options[:merchant_guid] if options.key?(:merchant_guid)

    delete_keys.each do |key|
      payload.delete key
    end

    return JOSE::JWT.sign(signing_key, { 'alg' => 'RS512' }, payload).compact if valid_signature

    JOSE::JWT.sign(generate_key, { 'alg' => 'RS512' }, payload).compact
  end
  # rubocop:enable Metrics/CyclomaticComplexity
  # rubocop:enable Metrics/PerceivedComplexity

  it "has a version number" do
    expect(TokenValidator::VERSION).not_to be nil
  end

  it "with malformed access token is not valid" do
    service = TokenValidator::TokenService.new(SecureRandom.base64(32) + "." + SecureRandom.base64(32) + "." + SecureRandom.base64(32), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (scope) is not valid" do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(delete_keys: [:scopes]), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (scope is incorrect) is not valid" do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(scopes: ['idp:api']), %w[test:api])
    expect(service.valid_access_token?).to be false
  end

  it 'with invalid access token (multiple scopes are missing) is not valid' do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(scopes: ['idp:api']), %w[test:api test:internal])
    expect(service.valid_access_token?).to be false
  end

  it 'with invalid access token (multiple scopes, only one matches) is invalid' do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(scopes: %w[test:internal]), %w[test:api test:internal])
    expect(service.valid_access_token?).to be false
  end

  it 'with valid access token (multiple scopes match) is valid' do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(scopes: %w[test:api test:internal]), %w[test:api test:internal])
    expect(service.valid_access_token?).to be true
  end

  it 'with valid access token (multiple scopes, all match) is valid' do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(scopes: %w[test:api test:internal idp:api]), %w[test:api test:internal])
    expect(service.valid_access_token?).to be true
  end

  it "with invalid access token (signature) is not valid" do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(valid_signature: false), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer not present) is not valid" do
    service = TokenValidator::TokenService.new(access_token(delete_keys: [:iss]), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer empty) is not valid" do
    service = TokenValidator::TokenService.new(access_token(issuer: ''), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer has http endpoint) is not valid" do
    service = TokenValidator::TokenService.new(access_token(issuer: 'http://example.com/.well-known/jwks.json'), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer has unknown host) is not valid" do
    service = TokenValidator::TokenService.new(access_token(issuer: 'https://www.evil.com/.well-known/jwks.json'), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (subject not present) is not valid" do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(delete_keys: %i[sub]), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with partner_guid not present is valid" do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token(delete_keys: %i[partner_guid]), expected_scopes)
    expect(service.valid_access_token?).to be true
  end

  it "with valid access token requests signature verification key" do
    stub_jwks_response
    service = TokenValidator::TokenService.new(access_token, expected_scopes)
    expect(service.valid_access_token?).to be true
    assert_requested :get, "#{issuer_url}/oauth/discovery/keys"
  end

  it "with incorrect cached signature verification key results in two request for signature verification key" do
    WebMock.reset!
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_return(status: 200, body: { keys: [JSON.parse(generate_key(SecureRandom.uuid).to_public.to_binary)] }.to_json)
      .then
      .to_return(status: 200, body: verification_jwks.to_json)

    TokenValidator::TokenService.new(access_token, expected_scopes).valid_access_token?
    assert_requested :get, "#{issuer_url}/oauth/discovery/keys", times: 2
  end

  it "with IdP offline access token is not valid" do
    WebMock.reset!
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_raise(Errno::ECONNREFUSED)

    service = TokenValidator::TokenService.new(access_token, expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with IdP unresponsive access token is not valid" do
    WebMock.reset!
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_raise(Errno::ETIMEDOUT)

    service = TokenValidator::TokenService.new(access_token, expected_scopes)
    expect(service.valid_access_token?).to be false
  end
end
