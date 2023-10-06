# frozen_string_literal: true

require 'spec_helper'

RSpec.describe TokenValidator::OauthTokenService, type: :request do
  let(:service) do
    described_class.instance
  end

  let(:issuer_url) do
    'https://localhost:3002'
  end

  before do
    service.clear
    TokenValidator::ValidatorConfig.configure(issuer_url:)
  end

  def stub_access_token_response
    stub_request(:post, "#{issuer_url}/oauth/token")
      .to_return(status: 200, body:
            '{"access_token":"abc123","token_type":"bearer",' \
            '"expires_in":7200,"refresh_token":"",' \
            '"scope":"idp:api"}')
  end

  it 'IdP is offline' do
    stub_request(:post, "#{issuer_url}/oauth/token").to_raise(Errno::ECONNREFUSED)
    expect(service.access_token).to be nil
  end

  it 'IdP is unresponsive' do
    stub_request(:post, "#{issuer_url}/oauth/token").to_raise(Errno::ETIMEDOUT)
    expect(service.access_token).to be nil
  end

  it 'handles new oauth token' do
    stub_request(:post, "#{issuer_url}/oauth/token")
      .to_return(status: 200, body:
            '{"access_token":"abc123","token_type":"bearer",' \
            '"expires_in":7200,"refresh_token":"",' \
            '"scope":"idp:api"}')
    expect(service.access_token).not_to be nil
    expect(service.access_token).to have_key(:token)
    expect(service.access_token).to have_value('abc123')
  end

  it 'handles unauthorized response' do
    stub_request(:post, "#{issuer_url}/oauth/token").to_return(status: 401)
    expect(service.access_token).to be nil
  end

  it 'gets new token when expired' do
    stub_access_token_response
    token1 = service.access_token

    Timecop.freeze(Time.now + 3.hours) do
      stub_access_token_response
      token2 = service.access_token
      expect(token1).not_to be(token2)
    end
  end

  it 'returns nil for empty access token' do
    stub_request(:get, "#{issuer_url}/oauth/token/info").to_return(status: 401)
    expect(service.get_token_info('')).to be nil
  end

  it 'returns nil for invalid access token' do
    stub_request(:get, "#{issuer_url}/oauth/token/info").to_return(status: 401)
    expect(service.get_token_info('some_random_token')).to be nil
  end

  it 'returns nil for idp offline' do
    stub_request(:get, "#{issuer_url}/oauth/token/info").to_raise(Errno::ECONNREFUSED)
    expect(service.get_token_info('some_random_token')).to be nil
  end

  it 'returns nil for idp unresponsive' do
    stub_request(:get, "#{issuer_url}/oauth/token/info").to_raise(Errno::ETIMEDOUT)
    expect(service.get_token_info('some_random_token')).to be nil
  end

  it 'returns hash for valid token' do
    valid_token = SecureRandom.hex(32)

    # rubocop:disable Style/StringConcatenation
    stub_request(:get, "#{issuer_url}/oauth/token/info")
      .with(headers: { 'Authorization' => "Bearer #{valid_token}" })
      .to_return(status: 200, body: '{"resource_owner_id":null,"scopes":["idp:api"],"expires_in_seconds":200,' \
        '"application":{"uid":"' + SecureRandom.hex(32) + '"},"created_at":' + 1.hour.ago.utc.to_i.to_s + '}')
    # rubocop:enable Style/StringConcatenation
    expect(service.get_token_info(valid_token)).not_to be nil
  end

  it 'returns headers hash for valid token' do
    stub_access_token_response
    expect(service.oauth_auth_header).to eq(authorization: "Bearer abc123")
  end

  it 'returns empty hash for oauth_auth_header for nil auth_token' do
    stub_request(:post, "#{issuer_url}/oauth/token").to_return(status: 401)
    expect(service.oauth_auth_header).to eq({})
  end

  it 'returns basic http authorization header for valid token' do
    access_token = SecureRandom.hex(32)
    stub_request(:post, "#{issuer_url}/oauth/token")
      .to_return(status: 200, body: { access_token:, token_type: :bearer, expires_in: 1800, refresh_token: '',
                                      scope: 'test:api' }.to_json)
    expect(service.basic_http_header).to eq(authorization: "Basic #{::Base64.strict_encode64("#{access_token}:")}")
  end

  it 'returns empty hash for basic http authorization header for nil auth_token' do
    stub_request(:post, "#{issuer_url}/oauth/token").to_return(status: 401)
    expect(service.basic_http_header).to eq({})
  end
end
