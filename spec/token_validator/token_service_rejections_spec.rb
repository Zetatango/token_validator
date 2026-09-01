# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# M1-04 (LEN-1077): every way a token can be untrustworthy is refused for *every* trusted issuer,
# not only the one this library used to assume.
#
# This is the file that decides whether multi-issuer support widened the attack surface. M1-03 can
# look finished while a rejection quietly stopped applying to the new issuer, because a passing
# valid-token suite says nothing about the invalid ones.
RSpec.describe TokenValidator::TokenService do
  include MultiIssuerTokens

  before do
    configure_issuers
    stub_every_issuer

    described_class.clear
  end

  after { TokenValidator::ValidatorConfig.additional_issuers = [] }

  def issuer_url_for(name)
    { 'the primary issuer' => primary_issuer, 'the vanity issuer' => vanity_issuer, 'Auth0' => auth0_issuer }.fetch(name)
  end

  def audience_for(name)
    name == 'Auth0' ? auth0_audience : primary_audience
  end

  def key_for(role)
    role == :auth0 ? auth0_key : roadrunner_key
  end

  def kid_for(role)
    role == :auth0 ? auth0_kid : roadrunner_kid
  end

  # A token for +issuer+, built the way that issuer's provider builds one, with any claim
  # overridden or deleted.
  def token_from(issuer, algorithm: nil, claim_overrides: {}, delete: [])
    payload = claims(issuer: issuer_url_for(issuer[:name]), audience: audience_for(issuer[:name]))
    payload[:kid] = kid_for(issuer[:key]) unless issuer[:key] == :auth0
    payload.merge!(claim_overrides)
    delete.each { |claim| payload.delete(claim) }
    headers = issuer[:key] == :auth0 ? { kid: auth0_kid } : {}

    JWT.encode(payload, key_for(issuer[:key]), algorithm || issuer[:algorithm], headers)
  end

  # Runs the same two checks `valid_access_token?` runs, but lets the exception out instead of
  # swallowing it, so an example can assert *which* rejection fired rather than only that one did.
  # The class is what a consumer rescues; the message is what alerting reads. This issue's contract
  # is that neither changes shape when the issuer does.
  def rejection_for(token)
    service = described_class.new(token, expected_scopes)
    service.send(:valid_structure?)
    service.send(:expired?)
    nil
  rescue TokenValidator::TokenService::TokenServiceException => e
    e
  end

  MultiIssuerTokens::ISSUERS.each do |issuer|
    describe "tokens from #{issuer[:name]}" do
      it 'refuses one minted for a different audience (TKV.09)' do
        bad = token_from(issuer, claim_overrides: { aud: 'https://somewhere.else.example.com' })

        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidAudienceException)
          .and have_attributes(message: 'Invalid audience')
        expect(validates?(bad)).to be false
      end

      it 'refuses one signed with an algorithm that is not this issuer\'s (TKV.10)' do
        bad = token_from(issuer, algorithm: issuer[:other_algorithm])

        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::JwtFormatException)
          .and have_attributes(message: 'Invalid token')
        expect(validates?(bad)).to be false
      end

      it 'refuses an expired one (TKV.12)' do
        bad = token_from(issuer, claim_overrides: { exp: (Time.now - 1.minute).to_i })

        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::ExpiredJwtException)
          .and have_attributes(message: 'Access token is expired')
        expect(validates?(bad)).to be false
      end

      it 'refuses one dated in the future' do
        bad = token_from(issuer, claim_overrides: { iat: (Time.now + 30.minutes).to_i })

        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::ExpiredJwtException)
        expect(validates?(bad)).to be false
      end

      it 'refuses one signed by a key the issuer does not publish' do
        bad = token_from(issuer, claim_overrides: {})
        forged = JWT.encode(JWT.decode(bad, nil, false).first, OpenSSL::PKey::RSA.new(2048), issuer[:algorithm],
                            issuer[:key] == :auth0 ? { kid: auth0_kid } : {})

        expect(rejection_for(forged)).to be_a(TokenValidator::TokenService::JwtFormatException)
        expect(validates?(forged)).to be false
      end

      # The crash this issue fixes: nil reached the clock comparison and ArgumentError escaped
      # `valid_access_token?`, whose contract is to answer true or false.
      MultiIssuerTokens::TIME_CLAIMS.each do |claim|
        it "refuses one with no #{claim}, rather than raising out of valid_access_token?" do
          bad = token_from(issuer, delete: [claim])

          expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::MissingAccessTokenField)
          expect { validates?(bad) }.not_to raise_error
          expect(validates?(bad)).to be false
        end
      end

      it 'accepts a well-formed one, so the refusals above are about the fault and not the issuer' do
        expect(validates?(token_from(issuer))).to be true
      end
    end
  end

  describe 'an issuer this library does not trust (TKV.08)' do
    # Each of these is one edit away from a trusted address. Matching is exact, so all of them are
    # strangers -- and none of them should reach a JWKS fetch, since that would let an untrusted
    # claim drive an outbound request.
    {
      'a suffix on a trusted host' => 'https://idp.example.com.evil.example/',
      'a trusted host as a prefix' => 'https://evil.example/https://idp.example.com/',
      'one character short' => 'https://idp.example.co/',
      'the canonical URL without its trailing slash' => 'https://idp.example.com',
      'the vanity URL with a trailing slash' => 'https://login.partner.example.com/',
      'a subdomain of the Auth0 tenant' => 'https://evil.tenant.ca.auth0.com/',
      'an empty issuer' => '',
      'a whitespace issuer' => '   '
    }.each do |description, issuer_url|
      it "refuses #{description}" do
        bad = JWT.encode(claims(issuer: issuer_url, audience: primary_audience).merge(kid: roadrunner_kid),
                         roadrunner_key, 'RS512')

        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidIssuerException)
          .and have_attributes(message: 'Invalid issuer')
        expect(a_request(:get, //)).not_to have_been_made
      end
    end

    it 'refuses a token with no iss claim at all' do
      bad = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience).merge(kid: roadrunner_kid).except(:iss),
                       roadrunner_key, 'RS512')

      expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidIssuerException)
    end
  end

  # `expired?` duplicates the expiry check the verifier already performs, and the verifier always
  # gets there first, so no behavioural example can tell that guard apart from its own absence. It
  # is the backstop if verification is ever configured not to check `exp`, so it is exercised
  # directly rather than left as a line whose deletion nothing notices.
  describe 'the expiry backstop' do
    it 'refuses an expired token on its own, without the verifier having caught it first' do
      bad = token_from(MultiIssuerTokens::ISSUERS.first, claim_overrides: { exp: (Time.now - 1.minute).to_i })

      expect { described_class.new(bad, expected_scopes).send(:expired?) }
        .to raise_error(TokenValidator::TokenService::ExpiredJwtException, 'Access token is expired')
    end
  end

  # REG.07: with the additional issuers taken away, every rejection above still behaves exactly as
  # it did before this library knew about more than one issuer.
  describe 'with no additional issuers configured' do
    before { TokenValidator::ValidatorConfig.additional_issuers = [] }

    it 'still accepts a primary-issuer token' do
      expect(validates?(roadrunner_token)).to be true
    end

    it 'still refuses a wrong audience with the same exception' do
      bad = roadrunner_token(audience: 'https://somewhere.else.example.com')

      expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidAudienceException)
    end

    it 'still refuses an expired token with the same exception' do
      bad = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                         .merge(kid: roadrunner_kid, exp: (Time.now - 1.minute).to_i), roadrunner_key, 'RS512')

      expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::ExpiredJwtException)
    end

    it 'refuses an issuer that was trusted only while it was configured' do
      expect(rejection_for(auth0_token)).to be_a(TokenValidator::TokenService::InvalidIssuerException)
    end
  end
end
