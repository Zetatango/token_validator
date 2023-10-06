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
    TokenValidator::ValidatorConfig.configure(issuer_url:, audience:)

    described_class.clear
  end

  def stub_jwks_response
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_return(status: 200, body: verification_jwks.to_json)
  end

  def verification_jwks
    { keys: [verification_key] }
  end

  def key_id
    @key_id ||= SecureRandom.uuid
  end

  def generate_key(kid = nil)
    optional_parameters = { kid: kid.nil? ? key_id : kid, use: 'sig', alg: 'RS512' }
    JWT::JWK.new(OpenSSL::PKey::RSA.new(4096), optional_parameters)
  end

  def current_key
    @current_key ||= generate_key
  end

  def signing_key
    current_key.signing_key
  end

  def verification_key
    current_key.verify_key.to_jwk(kid: key_id)
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
    expiry = options[:expiry] || (Time.now + 30.minutes).to_i
    issued_at = options[:issued_at] || Time.now.to_i

    payload = {
      sub: SecureRandom.hex(64),
      iat: issued_at,
      exp: expiry,
      jti: SecureRandom.uuid,
      kid: key_id,
      iss: issuer,
      aud:,
      partner_guid:,
      scopes:
    }

    payload[:merchant_guid] = options[:merchant_guid] if options.key?(:merchant_guid)

    delete_keys.each do |key|
      payload.delete key
    end

    return JWT.encode(payload, signing_key, 'RS512') if valid_signature

    JWT.encode(payload, generate_key.signing_key, 'RS512')
  end
  # rubocop:enable Metrics/CyclomaticComplexity
  # rubocop:enable Metrics/PerceivedComplexity

  it "has a version number" do
    expect(TokenValidator::VERSION).not_to be nil
  end

  it "with malformed access token is not valid" do
    stub_jwks_response
    service = described_class.new("#{SecureRandom.base64(32)}.#{SecureRandom.base64(32)}.#{SecureRandom.base64(32)}", expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (scope) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(delete_keys: [:scopes]), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (scope is incorrect) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(scopes: ['idp:api']), %w[test:api])
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (audience is incorrect) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(audience: 'https://example.com/'), %w[test:api])
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (iat is incorrect) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(issued_at: (Time.now + 30.minutes).to_i), %w[test:api])
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (exp is incorrect) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(expiry: (Time.now - 1.minutes).to_i), %w[test:api])
    expect(service.valid_access_token?).to be false
  end

  it 'with invalid access token (multiple scopes are missing) is not valid' do
    stub_jwks_response
    service = described_class.new(access_token(scopes: ['idp:api']), %w[test:api test:internal])
    expect(service.valid_access_token?).to be false
  end

  it 'with valid access token (multiple scopes, one matches) is valid' do
    stub_jwks_response
    service = described_class.new(access_token(scopes: %w[test:internal]), %w[test:api test:internal])
    expect(service.valid_access_token?).to be true
  end

  it 'with valid access token (multiple scopes match) is valid' do
    stub_jwks_response
    service = described_class.new(access_token(scopes: %w[test:api test:internal]), %w[test:api test:internal])
    expect(service.valid_access_token?).to be true
  end

  it 'with valid access token (multiple scopes, all match) is valid' do
    stub_jwks_response
    service = described_class.new(access_token(scopes: %w[test:api test:internal idp:api]), %w[test:api test:internal])
    expect(service.valid_access_token?).to be true
  end

  it 'with valid access token (no scopes expected, none given) is valid' do
    stub_jwks_response
    service = described_class.new(access_token(scopes: []), [])
    expect(service.valid_access_token?).to be true
  end

  it 'with valid access token (no scopes expected, some given) is valid' do
    stub_jwks_response
    service = described_class.new(access_token(scopes: ['idp:api']), [])
    expect(service.valid_access_token?).to be true
  end

  it "with invalid access token (signature) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(valid_signature: false), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer not present) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(delete_keys: [:iss]), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer empty) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(issuer: ''), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer has http endpoint) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(issuer: 'http://example.com/.well-known/jwks.json'), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (issuer has unknown host) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(issuer: 'https://www.evil.com/.well-known/jwks.json'), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with invalid access token (subject not present) is not valid" do
    stub_jwks_response
    service = described_class.new(access_token(delete_keys: %i[sub]), expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with partner_guid not present is valid" do
    stub_jwks_response
    service = described_class.new(access_token(delete_keys: %i[partner_guid]), expected_scopes)
    expect(service.valid_access_token?).to be true
  end

  it "with valid access token requests signature verification key" do
    stub_jwks_response
    service = described_class.new(access_token, expected_scopes)
    expect(service.valid_access_token?).to be true
    assert_requested :get, "#{issuer_url}/oauth/discovery/keys"
  end

  it "with incorrect cached signature verification key results in two request for signature verification key" do
    WebMock.reset!
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_return(status: 200, body: { keys: [generate_key.public_key.to_jwk] }.to_json)
      .then
      .to_return(status: 200, body: verification_jwks.to_json)

    described_class.new(access_token, expected_scopes).valid_access_token?
    assert_requested :get, "#{issuer_url}/oauth/discovery/keys", times: 2
  end

  it "with IdP offline access token is not valid" do
    WebMock.reset!
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_raise(Errno::ECONNREFUSED)

    service = described_class.new(access_token, expected_scopes)
    expect(service.valid_access_token?).to be false
  end

  it "with IdP unresponsive access token is not valid" do
    WebMock.reset!
    stub_request(:get, "#{issuer_url}/oauth/discovery/keys")
      .to_raise(Errno::ETIMEDOUT)

    service = described_class.new(access_token, expected_scopes)
    expect(service.valid_access_token?).to be false
  end
end
