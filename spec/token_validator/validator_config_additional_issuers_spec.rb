# frozen_string_literal: true

require 'spec_helper'

RSpec.describe TokenValidator::ValidatorConfig do
  let(:primary_issuer) { 'https://idp.example.com/' }
  let(:primary_audience) { 'https://primary.example.com' }
  let(:auth0_issuer) { 'https://tenant.ca.auth0.com/' }
  let(:auth0_entry) do
    {
      issuer_url: auth0_issuer,
      jwks_url: "#{auth0_issuer}.well-known/jwks.json",
      audience: 'https://api.example.com',
      algorithm: 'RS256'
    }
  end

  before do
    described_class.configure(
      issuer_url: primary_issuer,
      client_id: 'abc123',
      client_secret: 'secret123',
      requested_scope: 'test:scope',
      audience: primary_audience
    )
    described_class.additional_issuers = []
  end

  describe 'configuring additional issuers' do
    it 'defaults to an empty list' do
      expect(described_class.additional_issuers).to eq([])
    end

    it 'stores the configured entries' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.additional_issuers).to eq([auth0_entry])
    end

    it 'accepts string keys, as configure already does elsewhere' do
      described_class.configure('additional_issuers' => [auth0_entry.transform_keys(&:to_s)])
      expect(described_class.additional_issuers).to eq([auth0_entry])
    end

    it 'treats an explicit nil as unset, so a consumer with its flag off still boots' do
      described_class.configure(additional_issuers: [auth0_entry])
      described_class.configure(additional_issuers: nil)
      expect(described_class.additional_issuers).to eq([auth0_entry])
    end

    it 'leaves the config hash at exactly its original five keys' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.config.keys)
        .to contain_exactly(:issuer_url, :client_id, :client_secret, :requested_scope, :audience)
    end
  end

  describe '.issuer_config_for' do
    it 'returns the entry for a configured additional issuer' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.issuer_config_for(auth0_issuer)).to eq(auth0_entry)
    end

    it 'returns the primary configuration for the canonical issuer' do
      expect(described_class.issuer_config_for(primary_issuer)).to eq(
        issuer_url: primary_issuer,
        jwks_url: "#{primary_issuer}/oauth/discovery/keys",
        audience: primary_audience,
        algorithm: 'RS512'
      )
    end

    it 'resolves the primary issuer even with no additional issuers configured' do
      expect(described_class.issuer_config_for(primary_issuer)).not_to be_nil
    end

    it 'returns nil for an unknown issuer' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.issuer_config_for('https://attacker.example.com/')).to be_nil
    end

    it 'returns nil for a blank issuer' do
      expect(described_class.issuer_config_for(nil)).to be_nil
      expect(described_class.issuer_config_for('')).to be_nil
    end

    it 'matches exactly, not by prefix or suffix' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.issuer_config_for("#{auth0_issuer}extra")).to be_nil
      expect(described_class.issuer_config_for(auth0_issuer.chomp('/'))).to be_nil
    end
  end

  describe 'rejecting a malformed configuration' do
    it 'raises when the value is not an array' do
      expect { described_class.configure(additional_issuers: auth0_entry) }
        .to raise_error(described_class::InvalidIssuerConfigException, /must be an Array/)
    end

    it 'raises when an entry is not a hash' do
      expect { described_class.configure(additional_issuers: [auth0_issuer]) }
        .to raise_error(described_class::InvalidIssuerConfigException, /\[0\] must be a Hash/)
    end

    TokenValidator::ValidatorConfig::REQUIRED_ISSUER_KEYS.each do |required_key|
      it "raises when #{required_key} is missing" do
        expect { described_class.configure(additional_issuers: [auth0_entry.except(required_key)]) }
          .to raise_error(described_class::InvalidIssuerConfigException, /missing a value for #{required_key}/)
      end

      it "raises when #{required_key} is blank" do
        expect { described_class.configure(additional_issuers: [auth0_entry.merge(required_key => '  ')]) }
          .to raise_error(described_class::InvalidIssuerConfigException, /missing a value for #{required_key}/)
      end
    end

    it 'names the position and the key, but never the value' do
      expect { described_class.configure(additional_issuers: [auth0_entry, auth0_entry.merge(jwks_url: '')]) }
        .to raise_error(described_class::InvalidIssuerConfigException) do |error|
          expect(error.message).to include('additional_issuers[1]', 'jwks_url')
          expect(error.message).not_to include(auth0_entry[:audience])
        end
    end

    it 'ignores unrecognised extra keys' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(colour: 'blue')]) }
        .not_to raise_error
    end

    it 'leaves the previous configuration in place when it raises' do
      described_class.configure(additional_issuers: [auth0_entry])
      begin
        described_class.configure(additional_issuers: ['not a hash'])
      rescue described_class::InvalidIssuerConfigException # rubocop:disable Lint/SuppressedException
      end
      expect(described_class.additional_issuers).to eq([auth0_entry])
    end
  end
end
