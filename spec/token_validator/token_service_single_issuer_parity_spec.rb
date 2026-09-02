# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# M1-07 (LEN-1078), first half: the flag-off shape, which is what every consumer runs on the release
# that carries this work — `additional_issuers` empty, one issuer, no Auth0 anything.
#
# No consumer pins a version of this gem, so merging to master reaches four applications on their
# next dependency refresh with no version gate and no opt-in. These examples are the characterisation
# of that shape: each one pins an answer, an exception class and a message, so a later change cannot
# quietly move any of them.
#
# `bin/parity_check` proves the same matrix against the released 0.6.3 code by running both and
# diffing the transcripts. These examples keep the result pinned in CI, where the script cannot run.
RSpec.describe TokenValidator::TokenService do
  include MultiIssuerTokens

  before do
    TokenValidator::ValidatorConfig.configure(issuer_url: primary_issuer, audience: primary_audience,
                                              client_id: 'primary-client', client_secret: 'primary-secret',
                                              requested_scope: 'test:scope')
    TokenValidator::ValidatorConfig.additional_issuers = []
    stub_jwks(primary_jwks_url, roadrunner_key, roadrunner_kid, 'RS512')

    described_class.clear
  end

  describe 'what a single-issuer deployment still accepts (TKV.02)' do
    it 'accepts a well-formed token' do
      expect(validates?(roadrunner_token)).to be true
    end

    it 'fetches its keys from the double-slashed discovery address it has always used' do
      validates?(roadrunner_token)

      expect(a_request(:get, primary_jwks_url)).to have_been_made
    end

    it 'accepts a token with no partner_guid, as before' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience).merge(kid: roadrunner_kid),
                         roadrunner_key, 'RS512')

      expect(validates?(token)).to be true
    end
  end

  # Each row is answer, exception class, message. Written out rather than generated: an example
  # derived from the behaviour it is checking cannot notice that behaviour changing.
  describe 'what it still refuses, and how' do
    def rejection(token, required = expected_scopes)
      rejection_for(token, required)
    end

    it 'refuses an expired token' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                           .merge(kid: roadrunner_kid, exp: (Time.now - 1.minute).to_i), roadrunner_key, 'RS512')

      expect(rejection(token)).to be_a(TokenValidator::TokenService::ExpiredJwtException)
        .and have_attributes(message: 'Access token is expired')
    end

    it 'refuses a token minted for another audience' do
      expect(rejection(roadrunner_token(audience: 'https://elsewhere.example.com')))
        .to be_a(TokenValidator::TokenService::InvalidAudienceException).and have_attributes(message: 'Invalid audience')
    end

    it 'refuses an issuer it does not know' do
      expect(rejection(roadrunner_token(issuer: 'https://attacker.example.com/')))
        .to be_a(TokenValidator::TokenService::InvalidIssuerException).and have_attributes(message: 'Invalid issuer')
    end

    it 'refuses a malformed token' do
      expect(rejection("#{SecureRandom.base64(32)}.#{SecureRandom.base64(32)}.#{SecureRandom.base64(32)}"))
        .to be_a(TokenValidator::TokenService::JwtFormatException).and have_attributes(message: 'Invalid token')
    end

    it 'refuses a token with no subject' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                           .merge(kid: roadrunner_kid).except(:sub), roadrunner_key, 'RS512')

      expect(rejection(token)).to be_a(TokenValidator::TokenService::MissingAccessTokenField)
        .and have_attributes(message: 'Missing subject')
    end

    it 'refuses a token carrying no permission claim at all' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                           .merge(kid: roadrunner_kid).except(:scopes), roadrunner_key, 'RS512')

      expect(rejection(token)).to be_a(TokenValidator::TokenService::InvalidScope)
        .and have_attributes(message: 'Missing scopes')
    end

    it 'refuses a token without the required permission' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                           .merge(kid: roadrunner_kid, scopes: ['other:api']), roadrunner_key, 'RS512')

      expect(rejection(token)).to be_a(TokenValidator::TokenService::InvalidScope)
        .and have_attributes(message: 'Missing scope: require at least one of ["test:api"]')
    end

    it 'refuses a token signed by a key the issuer does not publish' do
      expect(rejection(roadrunner_token(key: OpenSSL::PKey::RSA.new(2048))))
        .to be_a(TokenValidator::TokenService::JwtFormatException)
    end

    # Reaches the library's own expiry check rather than the verifier's, which only looks at `exp`.
    it 'refuses a token dated in the future' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                         .merge(kid: roadrunner_kid, iat: (Time.now + 30.minutes).to_i), roadrunner_key, 'RS512')

      expect(rejection(token)).to be_a(TokenValidator::TokenService::ExpiredJwtException)
        .and have_attributes(message: 'Access token is expired')
    end

    it 'refuses a kid the issuer does not publish, after one retry' do
      expect(rejection(roadrunner_token(kid: 'no-such-kid')))
        .to be_a(TokenValidator::TokenService::InvalidSignatureKeyException)
      expect(a_request(:get, primary_jwks_url)).to have_been_made.twice
    end
  end

  # The nine scenarios where this gem no longer behaves as 0.6.3 behaved, each one deliberate: the
  # three no-fetch rejections (pinned by one representative example below plus the TKV.08 suite), the
  # three new acceptances, the two crashes turned into rejections, and the wrong-algorithm message
  # change. They are pinned so the *set* of intended
  # differences stays exactly this size: a tenth would be a behaviour change nobody decided on.
  describe 'where it deliberately differs from 0.6.3' do
    it 'rejects an untrusted issuer without fetching a JWKS, where 0.6.3 fetched first' do
      validates?(roadrunner_token(issuer: 'https://attacker.example.com/'))

      expect(a_request(:get, primary_jwks_url)).not_to have_been_made
    end

    it 'accepts a token whose permissions arrive as a space-separated string' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                           .merge(kid: roadrunner_kid).except(:scopes).merge(scope: 'test:api'), roadrunner_key, 'RS512')

      expect(validates?(token)).to be true
    end

    it 'accepts a token whose permissions arrive as a permissions list' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                           .merge(kid: roadrunner_kid).except(:scopes).merge(permissions: ['test:api']), roadrunner_key, 'RS512')

      expect(validates?(token)).to be true
    end

    it 'accepts a token carrying its kid in the JOSE header' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience), roadrunner_key, 'RS512',
                         { kid: roadrunner_kid })

      expect(validates?(token)).to be true
    end

    # Same answer as 0.6.3, different words. The class and the message both changed, and the message
    # is what a consumer's alerting reads -- which is why the parity harness captures the log line
    # and not only the answer. Without that, this difference is invisible.
    it 'names the algorithm when one does not match the issuer, where 0.6.3 said only "Invalid token"' do
      token = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience)
                         .merge(kid: roadrunner_kid), roadrunner_key, 'RS256')

      expect(rejection_for(token)).to be_a(TokenValidator::TokenService::InvalidAlgorithmException)
        .and have_attributes(message: 'Invalid algorithm: token names RS256, issuer is configured for RS512')
    end

    # 0.6.3 raised ArgumentError out of valid_access_token? for both of these.
    it 'refuses a token with no expiry instead of raising' do
      token = hand_built_token(payload: claims(issuer: primary_issuer, audience: primary_audience)
                                        .merge(kid: roadrunner_kid).except(:exp), key: roadrunner_key)

      expect { validates?(token) }.not_to raise_error
      expect(validates?(token)).to be false
    end

    it 'refuses a token with a null issued at instead of raising' do
      token = hand_built_token(payload: claims(issuer: primary_issuer, audience: primary_audience)
                                        .merge(kid: roadrunner_kid, iat: nil), key: roadrunner_key)

      expect { validates?(token) }.not_to raise_error
      expect(validates?(token)).to be false
    end
  end

  # The client half of the gem, which REG.07 covers as much as verification does.
  describe 'what it still sends' do
    it 'requests a machine token with exactly the parameters it always sent' do
      stub_request(:post, "#{primary_issuer}/oauth/token").to_return(status: 200, body: { access_token: 't', expires_in: 3600 }.to_json)

      TokenValidator::OauthTokenService.instance.access_token

      expect(a_request(:post, "#{primary_issuer}/oauth/token")
        .with(body: { grant_type: 'client_credentials', client_id: 'primary-client',
                      client_secret: 'primary-secret', scope: 'test:scope' })).to have_been_made
    end

    it 'still sends no audience, which is what the primary issuer expects' do
      stub_request(:post, "#{primary_issuer}/oauth/token").to_return(status: 200, body: { access_token: 't', expires_in: 3600 }.to_json)

      TokenValidator::OauthTokenService.instance.access_token

      expect(a_request(:post, "#{primary_issuer}/oauth/token").with { |req| req.body.include?('audience') }).not_to have_been_made
    end
  end
end
