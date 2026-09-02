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

        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidAlgorithmException)
          .and have_attributes(message: "Invalid algorithm: token names #{issuer[:other_algorithm]}, " \
                                        "issuer is configured for #{issuer[:algorithm]}")
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

  # `JWT.encode` refuses to mint these, so they are assembled by hand -- which is the only way they
  # ever arrive anyway: from an issuer emitting claims of the wrong type.
  #
  # Every one of them used to escape `valid_access_token?` as an ArgumentError or a NoMethodError,
  # and `exp: []` escaped from *inside the gem*, before any check of ours ran. That is why the type
  # check runs before signature verification rather than beside the subject check.
  describe 'time claims of the wrong type' do
    def token_claiming(overrides)
      hand_built_token(
        payload: claims(issuer: primary_issuer, audience: primary_audience).merge(kid: roadrunner_kid).merge(overrides),
        key: roadrunner_key
      )
    end

    {
      'a null issued at' => { iat: nil },
      'a null expiry' => { exp: nil },
      'an issued at that is a string' => { iat: 'yesterday' },
      'an expiry that is a string' => { exp: 'soon' },
      'an expiry that is a list' => { exp: [] },
      'an expiry that is an object' => { exp: { at: 1 } },
      'a not-before that is a list' => { nbf: [] }
    }.each do |description, overrides|
      it "refuses #{description} without raising out of valid_access_token?" do
        bad = token_claiming(overrides)

        expect { validates?(bad) }.not_to raise_error
        expect(validates?(bad)).to be false
        expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::MissingAccessTokenField)
      end
    end

    it 'accepts a not-before that is a number in the past' do
      expect(validates?(token_claiming(nbf: (Time.now - 1.minute).to_i))).to be true
    end

    # A float is a number: RFC 7519 NumericDate permits one, and the clock comparison handles it.
    it 'accepts time claims that are floats' do
      expect(validates?(token_claiming(iat: Time.now.to_f, exp: (Time.now + 30.minutes).to_f))).to be true
    end

    it 'still calls a token too malformed to read claims from malformed' do
      expect(rejection_for('not.a.token')).to be_a(TokenValidator::TokenService::JwtFormatException)
        .and have_attributes(message: 'Invalid token')
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

  # The algorithm rejection is deliberately its own exception rather than the generic one, so that
  # "someone is presenting the wrong algorithm for this issuer" can be told from "garbage arrived".
  # That only pays off if the message is both specific and safe to write to a log.
  describe 'what the algorithm rejection is allowed to say' do
    def token_with_raw_header(header)
      hand_built_token(header:, payload: claims(issuer: primary_issuer, audience: primary_audience).merge(kid: roadrunner_kid))
    end

    # HS256 is the dangerous claim -- under it the verification key *is* the signing key, and ours
    # is public JWKS material (LEN-1069). It is refused, and not repeated back into the log.
    it 'does not echo an algorithm outside the permitted set' do
      bad = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience).merge(kid: roadrunner_kid),
                       'secret', 'HS256')

      expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidAlgorithmException)
        .and have_attributes(message: 'Invalid algorithm: issuer is configured for RS512')
    end

    # `alg` is attacker-controlled text heading for a log line. Echoing it unfiltered would let a
    # token write its own entry; the permitted-set check means only our own constants are printed.
    it 'does not let a token forge a log line through alg' do
      bad = token_with_raw_header({ alg: "RS512\nWARN -- : Access token accepted", typ: 'JWT' })

      expect(rejection_for(bad)).to have_attributes(message: 'Invalid algorithm: issuer is configured for RS512')
    end

    it 'refuses a token that names no algorithm at all' do
      bad = token_with_raw_header({ typ: 'JWT' })

      expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::InvalidAlgorithmException)
        .and have_attributes(message: 'Invalid algorithm: issuer is configured for RS512')
    end

    # The distinction only means something if the generic rejection still exists for actual garbage.
    it 'still calls a malformed token malformed' do
      bad = "#{SecureRandom.base64(32)}.#{SecureRandom.base64(32)}.#{SecureRandom.base64(32)}"

      expect(rejection_for(bad)).to be_a(TokenValidator::TokenService::JwtFormatException)
        .and have_attributes(message: 'Invalid token')
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
