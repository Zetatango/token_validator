# frozen_string_literal: true

require 'spec_helper'

# What an additional issuer's token and key endpoints can send that must be refused rather than acted
# on: a redirect, a signing key that is not a public key, and an audience that would forge a log line
# when it is written into one. Each is an unusable response: a clean "nothing" answer, a single log
# line that carries nothing a response can forge, and no repeat request within the backoff.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'
  include_context 'with signed tokens'

  def orders_api = AdditionalIssuerContext::ORDERS_API
  def token_url = AdditionalIssuerContext::EXTRA_TOKEN_URL
  def jwks_url = AdditionalIssuerContext::EXTRA_JWKS_URL
  def elsewhere = 'https://elsewhere.example.com/landing'

  def redirect(status, location = elsewhere)
    { status:, headers: { 'Location' => location } }
  end

  before { use_cache }

  describe 'a redirect' do
    [
      ['301', 301, 'https://elsewhere.example.com/landing'],
      ['302', 302, 'https://elsewhere.example.com/landing'],
      ['303', 303, 'https://elsewhere.example.com/landing'],
      ['307', 307, 'https://elsewhere.example.com/landing'],
      ['308', 308, 'https://elsewhere.example.com/landing'],
      ['to a path on the same host', 302, '/oauth/other']
    ].each do |kind, status, location|
      it "from the token endpoint (#{kind}) is not followed: nil, an empty header, one request, and none to where it points" do
        stub_request(:post, token_url).to_return(redirect(status, location))
        stub_request(:any, elsewhere).to_return(status: 200, body: token_body('followed'))
        stub_request(:any, 'https://tenant.ca.auth0.com/oauth/other').to_return(status: 200, body: token_body('followed'))

        expect(token_for(orders_api)).to be_nil
        expect(service.oauth_auth_header(AdditionalIssuerContext::EXTRA_ISSUER, audience: orders_api)).to eq({})
        expect(requests_made).to eq(1)
      end

      it "from the key endpoint (#{kind}) is not followed: no keys, one request, and none to where it points" do
        stub_request(:get, jwks_url).to_return(redirect(status, location))
        stub_request(:any, elsewhere).to_return(key_set_response('followed'))
        stub_request(:any, 'https://tenant.ca.auth0.com/oauth/other').to_return(key_set_response('followed'))

        expect(extra_keys).to be_nil
        expect(refetched_extra_keys).to be_nil
        expect(requests_made).to eq(1)
      end
    end

    it 'is held back like any failed fetch: not asked again for 10 seconds, then asked again' do
      Timecop.freeze(Time.at(1_800_000_000))
      stub_request(:post, token_url).to_return(redirect(302))
      token_for(orders_api)

      Timecop.freeze(Time.at(1_800_000_000 + 10 - AdditionalIssuerContext::MILLISECOND)) { token_for(orders_api) }
      expect(token_requests(orders_api)).to have_been_made.once

      Timecop.freeze(Time.at(1_800_000_000 + 10 + AdditionalIssuerContext::MILLISECOND)) { token_for(orders_api) }
      expect(token_requests(orders_api)).to have_been_made.twice
    end

    it 'leaves the cached keys in place when a later refresh is redirected' do
      Timecop.freeze(Time.at(1_800_000_000))
      stub_request(:get, jwks_url).to_return(key_set_response('a'), redirect(301))
      extra_keys

      Timecop.freeze(Time.at(1_800_000_000 + 1.hour + 1.minute)) { expect(kids_of(extra_keys)).to eq(['a']) }
    end

    it 'logs one line that does not name where it points' do
      stub_request(:post, token_url).to_return(redirect(302))

      token_for(orders_api)

      expect(log_lines.string.lines.size).to eq(1)
      expect(log_lines.string).not_to include('elsewhere.example.com')
    end
  end

  describe 'a signing key that is not a public key' do
    def secret = 'a-shared-secret-of-the-issuer-that-must-never-verify-anything'
    def good_kid = 'good-kid'

    def oct_key
      { kty: 'oct', kid: 'shared-secret-kid', k: Base64.urlsafe_encode64(secret, padding: false), use: 'sig', alg: 'HS256' }
    end

    def extra_claims
      { sub: 'subject', iat: Time.now.to_i, exp: (Time.now + 30.minutes).to_i, jti: SecureRandom.uuid,
        iss: AdditionalIssuerContext::EXTRA_ISSUER, aud: AdditionalIssuerContext::ENTRY_API, scopes: ['test:api'] }
    end

    def token_signed_with_secret(algorithm: 'HS256')
      JWT.encode(extra_claims, secret, algorithm, { kid: oct_key[:kid] })
    end

    def token_signed_with_rsa(kid)
      JWT.encode(extra_claims, AdditionalIssuerContext::SIGNING_KEYS[kid], 'RS256', { kid: })
    end

    def publish(*keys)
      stub_request(:get, jwks_url).to_return(status: 200, body: { keys: }.to_json)
    end

    it 'is left out of the set, so a token naming it is refused, whichever algorithm it claims' do
      publish(oct_key, jwk(good_kid))

      expect(kids_of(extra_keys)).to eq([good_kid])
      %w[HS256 HS384 HS512].each { |algorithm| expect(validates?(token_signed_with_secret(algorithm:))).to be(false) }
    end

    it 'does not stop a token signed with a usable key in the same set from verifying' do
      publish(oct_key, jwk(good_kid))

      expect(validates?(token_signed_with_rsa(good_kid))).to be(true)
    end

    it 'refuses a token that names it and is signed with some other key' do
      publish(oct_key, jwk(good_kid))

      expect(validates?(JWT.encode(extra_claims, AdditionalIssuerContext::SIGNING_KEYS[good_kid], 'RS256', { kid: oct_key[:kid] }))).to be(false)
    end

    it 'leaves a set with no usable key unusable: no keys, a clean answer for every token, and no raise' do
      publish(oct_key)

      expect(extra_keys).to be_nil
      expect(validates?(token_signed_with_secret)).to be(false)
    end

    it 'is refused on a refetch for an unknown key id too' do
      publish(jwk(good_kid))
      extra_keys
      publish(oct_key, jwk(good_kid))
      Timecop.travel(Time.now + 61.seconds)

      expect(kids_of(refetched_extra_keys)).to eq([good_kid])
      expect(validates?(token_signed_with_secret)).to be(false)
    end
  end

  describe 'an audience that forges a log line' do
    forging_audiences = {
      'a newline' => "https://api.example.com/forged\nERROR -- : Logged in as admin",
      'a carriage return and line feed' => "https://api.example.com/forged\r\nERROR -- : Logged in as admin",
      'a terminal escape' => "https://api.example.com/forged\e[2J\e[31m",
      'a null byte' => "https://api.example.com/forged\u0000hidden",
      'a unicode line separator' => "https://api.example.com/forged ERROR -- : Logged in as admin"
    }

    def written
      log_lines.string
    end

    forging_audiences.each do |kind, audience|
      it "containing #{kind} is written as one line with no raw control character, when its token cannot be fetched" do
        stub_request(:post, token_url).to_return(status: 503)

        token_for(audience)

        expect(written.lines.size).to eq(1)
        expect(written.chomp).not_to match(/[\u0000-\u001f\u007f  ]/)
        expect(written).to include('https://api.example.com/forged')
      end

      it "containing #{kind} is written as one line with no raw control character, when its token lives too briefly" do
        stub_request(:post, token_url).to_return(status: 200, body: token_body('short', 100))

        token_for(audience)

        expect(written.lines.size).to eq(1)
        expect(written.chomp).not_to match(/[\u0000-\u001f\u007f  ]/)
        expect(written).to include('https://api.example.com/forged')
      end
    end

    it 'is still given its own token request, untouched, when the issuer answers' do
      audience = "https://api.example.com/odd\nname"
      stub_request(:post, token_url).to_return(status: 200, body: token_body('odd-token'))

      expect(token_for(audience)).to include(token: 'odd-token')
      expect(token_requests(audience)).to have_been_made.once
    end
  end
end
