# frozen_string_literal: true

require 'rspec/mocks'

RSpec.describe TokenValidator::GrapeAuthStrategy, type: :request do
  subject(:strategy_middleware) do
    authenticator = ->(token) { token[:properties][:info] == valid_info }
    described_class.new(app, auth_realm, &authenticator)
  end

  let(:auth_realm) { 'ZT Auth' }
  let(:valid_info) { 'valid' }

  let(:app) do
    lambda do |_env|
      [200, {
        'Content-Type' => 'text/plain'
      }, ['OK']]
    end
  end

  # rubocop:disable RSpec/LeakyConstantDeclaration, Lint/ConstantDefinitionInBlock
  class DummyEndpoint
    def initialize(scopes = ['ztt:api'])
      @scopes = scopes
    end

    def route_setting(*)
      # rubocop:disable RSpec/InstanceVariable
      @scopes
      # rubocop:enable RSpec/InstanceVariable
    end
  end
  # rubocop:enable RSpec/LeakyConstantDeclaration, Lint/ConstantDefinitionInBlock

  def setup_env(opts)
    endpoint = DummyEndpoint.new opts[:scopes]
    {
      "HTTP_AUTHORIZATION" => "#{opts[:scheme] || 'Bearer'} #{opts[:token]}",
      "api.endpoint" => endpoint
    }
  end

  def create_token(opts = {})
    {
      scopes: opts[:scopes] || ['ztt:api'],
      properties: {
        info: opts[:info] || valid_info
      }
    }
  end

  it 'Test valid request' do
    token = create_token

    mock_service = {}
    allow(TokenValidator::TokenService).to receive(:new).and_return(mock_service)
    allow(mock_service).to receive(:valid_access_token?).and_return(true)
    allow(mock_service).to receive(:decoded_jwt).and_return(token)

    env = setup_env(token:)
    response = strategy_middleware.call env
    expect(response[0]).to eq(200)
  end

  it 'Invalid information in token properties' do
    token = create_token info: "invalid"

    mock_service = {}
    allow(TokenValidator::TokenService).to receive(:new).and_return(mock_service)
    allow(mock_service).to receive(:valid_access_token?).and_return(true)
    allow(mock_service).to receive(:decoded_jwt).and_return(token)

    env = setup_env(token:)

    response = strategy_middleware.call env
    expect(response[0]).to eq(401)
  end

  it 'No bearer authorization header ' do
    token = create_token

    mock_service = {}
    allow(TokenValidator::TokenService).to receive(:new).and_return(mock_service)
    allow(mock_service).to receive(:valid_access_token?).and_return(true)
    allow(mock_service).to receive(:decoded_jwt).and_return(token)

    env = setup_env token:, scheme: "Basic"

    response = strategy_middleware.call env
    expect(response[0]).to eq(400)
  end

  it 'Token not valid' do
    token = create_token

    mock_service = {}
    allow(TokenValidator::TokenService).to receive(:new).and_return(mock_service)
    allow(mock_service).to receive(:valid_access_token?).and_return(false)
    allow(mock_service).to receive(:decoded_jwt).and_return(token)

    env = setup_env(token:)

    response = strategy_middleware.call env
    expect(response[0]).to eq(401)
  end

  it 'Bad token structure' do
    token = create_token

    mock_service = {}
    allow(TokenValidator::TokenService).to receive(:new).and_return(mock_service)
    allow(mock_service).to receive(:valid_access_token?).and_return(false)
    allow(mock_service).to receive(:decoded_jwt).and_raise("boom")

    env = setup_env(token:)

    response = strategy_middleware.call env
    expect(response[0]).to eq(401)
  end

  it 'Access token and scopes should be extracted and passed to token service' do
    mock_service = {}
    allow(TokenValidator::TokenService).to receive(:new).with("token", contain_exactly("ztt:other")).and_return(mock_service)
    allow(mock_service).to receive(:valid_access_token?).and_return(false)

    env = setup_env token: "token", scopes: ["ztt:other"]
    response = strategy_middleware.call env
    expect(response[0]).to eq(401)
  end
end
