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
    described_class.configure(default_config)
  end

  it "logger set directly is not nil" do
    described_class.logger = Logger.new(STDOUT)
    expect(described_class.logger).not_to be nil
    expect(described_class.logger.is_a?(Logger)).to be true
  end

  it 'config does not set key/value for unknown key' do
    described_class.configure(foo: 'bar')
    expect(described_class.config).to eq(default_config)
  end

  it 'config sets issuer_url to a known value' do
    described_class.configure(issuer_url: 'https://example.com')
    expect(described_class.config).to have_key(:issuer_url)
    expect(described_class.config).to have_value('https://example.com')
  end

  it 'config sets client ID to a known value' do
    described_class.configure(client_id: 'abc123')
    expect(described_class.config).to have_key(:client_id)
    expect(described_class.config).to have_value('abc123')
  end

  it 'config sets client secret to a known value' do
    described_class.configure(client_secret: 'secret123')
    expect(described_class.config).to have_key(:client_secret)
    expect(described_class.config).to have_value('secret123')
  end

  it 'config sets requested scope to a known value' do
    described_class.configure(requested_scope: 'test:scope')
    expect(described_class.config).to have_key(:requested_scope)
    expect(described_class.config).to have_value('test:scope')
  end

  it 'config sets audience to a known value' do
    described_class.configure(audience: 'https://localhost:3000')
    expect(described_class.config).to have_key(:audience)
    expect(described_class.config).to have_value('https://localhost:3000')
  end
end
