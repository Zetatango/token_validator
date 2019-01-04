# frozen_string_literal: true

require 'spec_helper'

RSpec.describe TokenValidator::ValidatorConfig, type: :request do
  let(:default_config) do
    { issuer_url: '',
      client_id: '',
      client_secret: '',
      audience: '',
      requested_scope: '' }
  end

  before do
    TokenValidator::ValidatorConfig.configure(default_config)
  end

  it "logger set directly is not nil" do
    TokenValidator::ValidatorConfig.logger = Logger.new(STDOUT)
    expect(TokenValidator::ValidatorConfig.logger).not_to be nil
    expect(TokenValidator::ValidatorConfig.logger.is_a?(Logger)).to be true
  end

  it 'config does not set key/value for unknown key' do
    TokenValidator::ValidatorConfig.configure(foo: 'bar')
    expect(TokenValidator::ValidatorConfig.config).to eq(default_config)
  end

  it 'config sets issuer_url to a known value' do
    TokenValidator::ValidatorConfig.configure(issuer_url: 'https://example.com')
    expect(TokenValidator::ValidatorConfig.config).to have_key(:issuer_url)
    expect(TokenValidator::ValidatorConfig.config).to have_value('https://example.com')
  end

  it 'config sets client ID to a known value' do
    TokenValidator::ValidatorConfig.configure(client_id: 'abc123')
    expect(TokenValidator::ValidatorConfig.config).to have_key(:client_id)
    expect(TokenValidator::ValidatorConfig.config).to have_value('abc123')
  end

  it 'config sets client secret to a known value' do
    TokenValidator::ValidatorConfig.configure(client_secret: 'secret123')
    expect(TokenValidator::ValidatorConfig.config).to have_key(:client_secret)
    expect(TokenValidator::ValidatorConfig.config).to have_value('secret123')
  end

  it 'config sets requested scope to a known value' do
    TokenValidator::ValidatorConfig.configure(requested_scope: 'test:scope')
    expect(TokenValidator::ValidatorConfig.config).to have_key(:requested_scope)
    expect(TokenValidator::ValidatorConfig.config).to have_value('test:scope')
  end

  it 'config sets audience to a known value' do
    TokenValidator::ValidatorConfig.configure(audience: 'https://localhost:3000')
    expect(TokenValidator::ValidatorConfig.config).to have_key(:audience)
    expect(TokenValidator::ValidatorConfig.config).to have_value('https://localhost:3000')
  end
end
