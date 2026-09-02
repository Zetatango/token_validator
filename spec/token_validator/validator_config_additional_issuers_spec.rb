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

    it 'matches an additional issuer exactly, not by prefix or suffix' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.issuer_config_for("#{auth0_issuer}extra")).to be_nil
      expect(described_class.issuer_config_for(auth0_issuer.chomp('/'))).to be_nil
    end

    # The primary issuer is the highest-value one to spoof, so its matching gets the same
    # scrutiny as the additional issuers rather than being assumed correct.
    it 'matches the primary issuer exactly, not by prefix or suffix' do
      expect(described_class.issuer_config_for("#{primary_issuer}evil")).to be_nil
      expect(described_class.issuer_config_for(primary_issuer.chomp('/'))).to be_nil
    end

    # With no issuer_url configured, a token carrying no issuer must not match the primary
    # by both being empty. Without the blank guard this returns a config rather than nil.
    it 'trusts nothing when the library itself is unconfigured' do
      described_class.configure(issuer_url: '', audience: '')
      expect(described_class.issuer_config_for('')).to be_nil
      expect(described_class.issuer_config_for(nil)).to be_nil
    end

    it 'returns frozen results, so a caller cannot corrupt shared configuration' do
      described_class.configure(additional_issuers: [auth0_entry])
      expect(described_class.issuer_config_for(auth0_issuer)).to be_frozen
      expect(described_class.issuer_config_for(primary_issuer)).to be_frozen
      expect(described_class.additional_issuers).to be_frozen
    end

    it 'still answers with an empty list if the backing store was never initialised' do
      described_class.remove_instance_variable(:@additional_issuers)
      expect(described_class.additional_issuers).to eq([])
      expect(described_class.issuer_config_for(auth0_issuer)).to be_nil
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

    it 'drops unrecognised extra keys rather than carrying them along' do
      described_class.configure(additional_issuers: [auth0_entry.merge(colour: 'blue')])
      expect(described_class.issuer_config_for(auth0_issuer)).to eq(auth0_entry)
    end

    it 'ignores a key that cannot be symbolised, rather than raising NoMethodError' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(1 => 'x')]) }
        .not_to raise_error
    end

    it 'still raises its own exception when such an entry is also malformed' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(1 => 'x', jwks_url: '')]) }
        .to raise_error(described_class::InvalidIssuerConfigException, /missing a value for jwks_url/)
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

  describe 'rejecting a dangerous signing algorithm' do
    # Asserted rather than assumed: the synthesised primary entry has to satisfy the same
    # rule as a configured one, or M1-03 would honour a value this list would have refused.
    it 'permits the algorithm the primary issuer already uses' do
      expect(described_class::PERMITTED_ISSUER_ALGORITHMS)
        .to include(described_class::PRIMARY_ISSUER_ALGORITHM)
    end

    it 'leaves the primary issuer resolving as it always has' do
      expect(described_class.issuer_config_for(primary_issuer)[:algorithm]).to eq('RS512')
    end

    # Spelled out literally rather than derived from the constant. The per-algorithm
    # examples below iterate the constant, so on their own they would shrink silently with
    # it -- delete PS512 from the allowlist and its example disappears instead of failing.
    # This is the assertion that notices.
    it 'permits exactly the asymmetric algorithms, and nothing else' do
      expect(described_class::PERMITTED_ISSUER_ALGORITHMS).to contain_exactly(
        'RS256', 'RS384', 'RS512',
        'ES256', 'ES384', 'ES512',
        'PS256', 'PS384', 'PS512'
      )
    end

    TokenValidator::ValidatorConfig::PERMITTED_ISSUER_ALGORITHMS.each do |algorithm|
      # Checks the value survives into the stored entry, not merely that nothing raised:
      # a spec that only asserts the absence of an exception passes against a gutted method.
      it "accepts #{algorithm} and keeps it" do
        described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: algorithm)])
        expect(described_class.issuer_config_for(auth0_issuer)[:algorithm]).to eq(algorithm)
      end
    end

    %w[HS256 HS384 HS512 none].each do |algorithm|
      it "refuses #{algorithm} and names it" do
        expect { described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: algorithm)]) }
          .to raise_error(described_class::InvalidIssuerConfigException, /names algorithm "#{algorithm}"/)
      end
    end

    # The jwt gem resolves alg case-insensitively, so a lowercased HMAC name is not a
    # harmless typo -- it is the same bypass wearing different case.
    it 'refuses a lowercased HMAC name too' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: 'hs256')]) }
        .to raise_error(described_class::InvalidIssuerConfigException, /names algorithm "hs256"/)
    end

    # Pinned deliberately (LEN-1069 asked for a ruling): exact RFC 7518 spelling is
    # required. jwt would resolve 'rs256', but accepting it would store a value that no
    # longer equals the canonical name, so it fails at boot as the typo it is.
    it 'refuses a lowercased asymmetric name, rather than quietly correcting it' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: 'rs256')]) }
        .to raise_error(described_class::InvalidIssuerConfigException, /names algorithm "rs256"/)
    end

    it 'refuses a symbol, which is not the string the verifier will compare' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: :RS256)]) }
        .to raise_error(described_class::InvalidIssuerConfigException, /names algorithm :RS256/)
    end

    it 'names the position and the algorithm, but no other value from the entry' do
      expect { described_class.configure(additional_issuers: [auth0_entry, auth0_entry.merge(algorithm: 'HS256')]) }
        .to raise_error(described_class::InvalidIssuerConfigException) do |error|
          expect(error.message).to include('additional_issuers[1]', 'HS256')
          expect(error.message).not_to include(auth0_entry[:audience], auth0_entry[:jwks_url])
        end
    end

    # Order matters: a blank algorithm is a missing value, not an unsupported one, and the
    # operator gets the message that actually describes what they left out.
    it 'reports a blank algorithm as missing rather than as unsupported' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: '')]) }
        .to raise_error(described_class::InvalidIssuerConfigException, /missing a value for algorithm/)
    end

    it 'rejects the whole configuration, not just the offending entry' do
      expect { described_class.configure(additional_issuers: [auth0_entry.merge(algorithm: 'HS256')]) }
        .to raise_error(described_class::InvalidIssuerConfigException)
      expect(described_class.additional_issuers).to eq([])
    end
  end

  # The entry Hash was already frozen; its Strings were not. Values arrive mutable in practice --
  # `ENV['x']` returns a new unfrozen String on every read -- so a caller could `replace` a value
  # after validation and defeat the checks that ran at configuration time.
  describe 'values are stored beyond the reach of later mutation' do
    let(:mutable_entry) do
      { issuer_url: +'https://tenant.ca.auth0.com/', jwks_url: +'https://tenant.ca.auth0.com/.well-known/jwks.json',
        audience: +'https://platform.example.com', algorithm: +'RS256',
        client_id: +'auth0-client', client_secret: +'auth0-secret', token_url: +'https://tenant.ca.auth0.com/oauth/token' }
    end

    before { described_class.additional_issuers = [mutable_entry] }

    def stored = described_class.additional_issuers.first

    %i[issuer_url jwks_url audience algorithm client_id client_secret token_url].each do |key|
      it "freezes the stored #{key}" do
        expect(stored[key]).to be_frozen
      end
    end

    # The two that matter most: the algorithm is what the allowlist guards, and the issuer URL is
    # what selection matches on.
    it 'refuses a post-storage algorithm change that would bypass the allowlist' do
      expect { stored[:algorithm].replace('HS256') }.to raise_error(FrozenError)
      expect(stored[:algorithm]).to eq('RS256')
    end

    it 'refuses a post-storage issuer change that would make an unconfigured address resolve' do
      expect { stored[:issuer_url].replace('https://attacker.example.com/') }.to raise_error(FrozenError)
      expect(described_class.issuer_config_for('https://attacker.example.com/')).to be_nil
    end

    # A copy is stored, so freezing is never a side effect on an object the caller still holds.
    it 'leaves the caller\'s own strings alone' do
      expect(mutable_entry[:algorithm]).not_to be_frozen
    end
  end
end
