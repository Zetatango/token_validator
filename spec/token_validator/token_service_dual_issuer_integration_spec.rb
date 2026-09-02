# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# M1-07 (LEN-1078), second half: the gem with two issuers configured at once, which is the state
# every consumer will actually run in and the one no earlier issue exercised.
#
# Everything here is interleaved on purpose. `OauthTokenService` is a `Singleton`, so a spec that
# sets up one issuer, asserts, tears down and then does the same for the other cannot see shared
# state at all -- each issuer would be looking at a fresh world. Only alternating between them
# inside a single example can.
RSpec.describe TokenValidator::TokenService do
  include MultiIssuerTokens

  let(:auth0_credentials) { auth0_entry.merge(client_id: 'auth0-client', client_secret: 'auth0-secret') }

  before do
    TokenValidator::ValidatorConfig.configure(issuer_url: primary_issuer, audience: primary_audience,
                                              client_id: 'primary-client', client_secret: 'primary-secret',
                                              requested_scope: 'test:scope')
    TokenValidator::ValidatorConfig.additional_issuers = [vanity_entry, auth0_credentials]
    stub_every_issuer

    described_class.clear
  end

  after { TokenValidator::ValidatorConfig.additional_issuers = [] }

  describe 'both issuers in one run' do
    it 'validates tokens from all three trusted addresses, alternating' do
      expect(validates?(roadrunner_token)).to be true
      expect(validates?(auth0_token)).to be true
      expect(validates?(roadrunner_token(issuer: vanity_issuer))).to be true
      expect(validates?(auth0_token)).to be true
      expect(validates?(roadrunner_token)).to be true
    end

    # If the answer depends on who went first, something is being shared that should not be.
    it 'gives the same answers whichever issuer goes first' do
      auth0_first = [validates?(auth0_token), validates?(roadrunner_token)]
      described_class.clear
      roadrunner_first = [validates?(roadrunner_token), validates?(auth0_token)].reverse

      expect(auth0_first).to eq(roadrunner_first)
    end

    it 'is not knocked off course by a rejection in the middle' do
      expect(validates?(roadrunner_token)).to be true
      expect(validates?(auth0_token(key: roadrunner_key, kid: roadrunner_kid, algorithm: 'RS512'))).to be false
      expect(validates?(auth0_token)).to be true
      expect(validates?(roadrunner_token)).to be true
    end

    it 'sends each issuer only to its own address' do
      validates?(auth0_token)
      validates?(roadrunner_token)
      validates?(roadrunner_token(issuer: vanity_issuer))

      expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
      expect(a_request(:get, primary_jwks_url)).to have_been_made.once
      expect(a_request(:get, vanity_jwks_url)).to have_been_made.once
    end
  end

  describe 'verification and machine tokens in the same run' do
    before do
      stub_request(:post, "#{primary_issuer}/oauth/token")
        .to_return(status: 200, body: { access_token: 'primary-machine-token', expires_in: 3600 }.to_json)
      stub_request(:post, 'https://tenant.ca.auth0.com/oauth/token')
        .to_return(status: 200, body: { access_token: 'auth0-machine-token', expires_in: 3600 }.to_json)
    end

    # The Singleton keeps one scratch slot for the primary issuer's token. Asking for another
    # issuer's must not land in it, and interleaving is the only way to notice if it does.
    it 'keeps each issuer\'s machine token to itself while validating tokens between calls' do
      expect(TokenValidator::OauthTokenService.instance.access_token[:token]).to eq('primary-machine-token')
      expect(validates?(auth0_token)).to be true
      expect(TokenValidator::OauthTokenService.instance.access_token(auth0_issuer)[:token]).to eq('auth0-machine-token')
      expect(validates?(roadrunner_token)).to be true
      expect(TokenValidator::OauthTokenService.instance.access_token[:token]).to eq('primary-machine-token')
    end

    it 'never sends one issuer\'s credentials to the other' do
      TokenValidator::OauthTokenService.instance.access_token(auth0_issuer)

      expect(a_request(:post, 'https://tenant.ca.auth0.com/oauth/token')
        .with { |req| req.body.include?('primary-secret') }).not_to have_been_made
    end

    it 'gives an issuer with no credentials no token, rather than the primary issuer\'s' do
      expect(TokenValidator::OauthTokenService.instance.access_token(vanity_issuer)).to be_nil
    end
  end

  describe 'with a real cache holding both issuers' do
    before { with_cache }

    it 'serves each issuer from its own cached keys across interleaved validations' do
      3.times do
        expect(validates?(roadrunner_token)).to be true
        expect(validates?(auth0_token)).to be true
      end

      expect(a_request(:get, primary_jwks_url)).to have_been_made.once
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
    end

    # The retry an unknown kid triggers is the one moment this gem throws cached state away.
    it 'leaves the other issuer\'s cache alone when one issuer retries an unknown kid' do
      validates?(auth0_token)
      validates?(roadrunner_token)

      validates?(auth0_token(kid: 'no-such-kid'))

      expect(validates?(roadrunner_token)).to be true
      # Both halves matter: the issuer that retried really did go back for its keys, and the other
      # one never did. Asserting only the second passes just as well when nothing is evicted at all.
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
      expect(a_request(:get, primary_jwks_url)).to have_been_made.once
    end

    it 'clears every issuer when asked to clear' do
      validates?(roadrunner_token)
      validates?(auth0_token)

      described_class.clear

      validates?(roadrunner_token)
      validates?(auth0_token)
      expect(a_request(:get, primary_jwks_url)).to have_been_made.twice
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
    end
  end

  # The shape every consumer ships first: the second issuer configured, and no traffic from it yet.
  describe 'a second issuer configured but unused' do
    it 'never contacts the issuer nobody is presenting tokens from' do
      5.times { expect(validates?(roadrunner_token)).to be true }

      expect(a_request(:get, auth0_jwks_url)).not_to have_been_made
      expect(a_request(:post, 'https://tenant.ca.auth0.com/oauth/token')).not_to have_been_made
    end

    it 'answers exactly as it does with no additional issuers at all' do
      with_auth0 = [validates?(roadrunner_token), validates?(roadrunner_token(audience: 'https://elsewhere.example.com')),
                    validates?(roadrunner_token(kid: 'no-such-kid'))]

      TokenValidator::ValidatorConfig.additional_issuers = []
      described_class.clear
      without_auth0 = [validates?(roadrunner_token), validates?(roadrunner_token(audience: 'https://elsewhere.example.com')),
                       validates?(roadrunner_token(kid: 'no-such-kid'))]

      expect(with_auth0).to eq(without_auth0)
    end

    it 'refuses an Auth0 token the moment that issuer is taken out of the configuration' do
      expect(validates?(auth0_token)).to be true

      TokenValidator::ValidatorConfig.additional_issuers = []
      described_class.clear

      expect(validates?(auth0_token)).to be false
    end
  end
end
