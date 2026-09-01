# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# RSA generation dominates the runtime of this file, and these keys carry no meaning beyond being
# distinct from one another, so each is generated once and reused across examples.
module TokenServiceMultiIssuerSpec
  KEYS = Hash.new { |keys, name| keys[name] = OpenSSL::PKey::RSA.new(2048) }

  # The cache namespace is derived from Rails.application's module name, which does not exist in
  # this suite. A named stand-in lets the real namespace code run rather than stubbing it out.
  Application = Class.new
end

# M1-03 (LEN-1076): a token is verified against whichever trusted issuer signed it, rather than
# against the one provider this library used to assume.
#
# token_service_spec.rb is left unedited beside this file, as the record that single-issuer
# behaviour is unchanged (REG.07).
RSpec.describe TokenValidator::TokenService do
  # The canonical primary issuer carries a trailing slash in every environment, which is why its
  # discovery address has always had a double slash in it. The vanity address does not carry one.
  # That asymmetry is why exact matching is worth proving rather than assuming.
  def primary_issuer = 'https://idp.example.com/'
  def primary_jwks_url = 'https://idp.example.com//oauth/discovery/keys'
  def primary_audience = 'https://api.example.com'

  # A second trusted address for the *same* provider: a partner-branded URL, publishing the same
  # keys under the same algorithm, differing only in what its tokens put in `iss`.
  def vanity_issuer = 'https://login.partner.example.com'
  def vanity_jwks_url = "#{vanity_issuer}/oauth/discovery/keys"

  def auth0_issuer = 'https://tenant.ca.auth0.com/'
  def auth0_jwks_url = "#{auth0_issuer}.well-known/jwks.json"
  def auth0_audience = 'https://platform.example.com'

  def roadrunner_key = TokenServiceMultiIssuerSpec::KEYS[:roadrunner]
  def auth0_key = TokenServiceMultiIssuerSpec::KEYS[:auth0]
  def roadrunner_kid = 'roadrunner-kid'
  def auth0_kid = 'auth0-kid'

  def expected_scopes = ['test:api']

  def vanity_entry
    { issuer_url: vanity_issuer, jwks_url: vanity_jwks_url, audience: primary_audience, algorithm: 'RS512' }
  end

  def auth0_entry
    { issuer_url: auth0_issuer, jwks_url: auth0_jwks_url, audience: auth0_audience, algorithm: 'RS256' }
  end

  before do
    TokenValidator::ValidatorConfig.configure(issuer_url: primary_issuer, audience: primary_audience)
    TokenValidator::ValidatorConfig.additional_issuers = [vanity_entry, auth0_entry]

    described_class.clear
  end

  # ValidatorConfig holds class-level state and this is the only file that leaves additional issuers
  # configured. Clearing them keeps the single-issuer specs measuring what they claim to, whatever
  # order the suite runs in.
  after { TokenValidator::ValidatorConfig.additional_issuers = [] }

  def stub_jwks(url, key, kid, algorithm)
    body = { keys: [key.public_key.to_jwk(kid:, use: 'sig', alg: algorithm)] }.to_json
    stub_request(:get, url).to_return(status: 200, body:)
  end

  # Both roadrunner addresses publish the same key, because they are the same provider.
  def stub_every_issuer
    stub_jwks(primary_jwks_url, roadrunner_key, roadrunner_kid, 'RS512')
    stub_jwks(vanity_jwks_url, roadrunner_key, roadrunner_kid, 'RS512')
    stub_jwks(auth0_jwks_url, auth0_key, auth0_kid, 'RS256')
  end

  def claims(issuer:, audience:)
    { sub: SecureRandom.hex(16), iat: Time.now.to_i, exp: (Time.now + 30.minutes).to_i,
      jti: SecureRandom.uuid, iss: issuer, aud: audience, scopes: ['test:api'] }
  end

  # Each token shape is built the way its own provider builds it, because the two disagree about
  # where `kid` belongs: roadrunner writes it into the payload, Auth0 into the JOSE header.
  def roadrunner_token(issuer: primary_issuer, key: roadrunner_key, kid: roadrunner_kid, algorithm: 'RS512', audience: primary_audience)
    JWT.encode(claims(issuer:, audience:).merge(kid:), key, algorithm)
  end

  def auth0_token(issuer: auth0_issuer, key: auth0_key, kid: auth0_kid, algorithm: 'RS256', audience: auth0_audience)
    JWT.encode(claims(issuer:, audience:), key, algorithm, { kid: })
  end

  def validates?(token)
    described_class.new(token, expected_scopes).valid_access_token?
  end

  def cache
    @cache ||= ActiveSupport::Cache::MemoryStore.new
  end

  # Rails.cache is nil throughout this suite, so nothing here is cached by default. Giving it a real
  # store is the only way to test what an eviction does and does not reach.
  def with_cache
    allow(Rails).to receive_messages(cache: cache, application: TokenServiceMultiIssuerSpec::Application.new)
  end

  describe 'a token from each issuer this library trusts' do
    before { stub_every_issuer }

    it 'validates a roadrunner RS512 token, exactly as before (TKV.05)' do
      expect(validates?(roadrunner_token)).to be true
      expect(a_request(:get, primary_jwks_url)).to have_been_made
    end

    it 'validates an Auth0 RS256 token (TKV.06)' do
      expect(validates?(auth0_token)).to be true
      expect(a_request(:get, auth0_jwks_url)).to have_been_made
    end

    it 'validates a token whose iss is the partner vanity URL (TKV.07)' do
      expect(validates?(roadrunner_token(issuer: vanity_issuer))).to be true
      expect(a_request(:get, vanity_jwks_url)).to have_been_made
    end

    # The vanity issuer is a separate entry, not an alias resolved through the canonical one.
    it 'fetches the vanity issuer from its own address and not the canonical one' do
      validates?(roadrunner_token(issuer: vanity_issuer))

      expect(a_request(:get, primary_jwks_url)).not_to have_been_made
    end

    it 'never reaches for the primary issuer keys when validating an Auth0 token' do
      validates?(auth0_token)

      expect(a_request(:get, primary_jwks_url)).not_to have_been_made
    end
  end

  describe 'issuer matching is exact' do
    before { stub_every_issuer }

    # The canonical issuer's trailing slash is part of its identity. A token missing it names an
    # address this library does not trust, however similar it looks.
    #
    # Both examples assert that nothing was fetched, and that assertion is the load-bearing half.
    # Rejection on its own proves little here: a near-miss that *did* resolve to an entry would
    # still be rejected further down, by the issuer check inside the verifier. Only the absent
    # fetch shows the near-miss matched no entry in the first place.
    it 'rejects the canonical issuer URL with its trailing slash removed' do
      expect(validates?(roadrunner_token(issuer: primary_issuer.chomp('/')))).to be false
      expect(a_request(:get, primary_jwks_url)).not_to have_been_made
    end

    it 'rejects the vanity issuer URL with a trailing slash added' do
      expect(validates?(roadrunner_token(issuer: "#{vanity_issuer}/"))).to be false
      expect(a_request(:get, vanity_jwks_url)).not_to have_been_made
    end

    it 'rejects an issuer that is not configured at all (TKV.08)' do
      expect(validates?(roadrunner_token(issuer: 'https://attacker.example.com/'))).to be false
    end

    # An untrusted `iss` used to drive a JWKS fetch before it was rejected. Now nothing is fetched
    # on the strength of a claim from a token no configured issuer signed.
    it 'fetches nothing at all for an issuer it does not trust' do
      validates?(roadrunner_token(issuer: 'https://attacker.example.com/'))

      expect(a_request(:get, //)).not_to have_been_made
    end
  end

  describe 'a token signed by an issuer other than the one it names (TKV.11)' do
    before { stub_every_issuer }

    it 'rejects a roadrunner-signed token claiming to come from Auth0' do
      cross_signed = auth0_token(key: roadrunner_key, kid: roadrunner_kid, algorithm: 'RS512')

      expect(validates?(cross_signed)).to be false
    end

    it 'rejects an Auth0-signed token claiming to come from roadrunner' do
      cross_signed = roadrunner_token(key: auth0_key, kid: auth0_kid, algorithm: 'RS256')

      expect(validates?(cross_signed)).to be false
    end

    it 'rejects an Auth0-signed token claiming to come from the vanity issuer' do
      cross_signed = roadrunner_token(issuer: vanity_issuer, key: auth0_key, kid: auth0_kid, algorithm: 'RS256')

      expect(validates?(cross_signed)).to be false
    end

    # The harder shape: the named issuer really does publish a key under this `kid`, so the token
    # is matched to a key and rejected by the signature check rather than by failing to find one.
    it 'rejects a token whose kid matches a key the named issuer publishes but did not sign with' do
      stub_jwks(auth0_jwks_url, auth0_key, roadrunner_kid, 'RS256')
      colliding = auth0_token(key: roadrunner_key, kid: roadrunner_kid, algorithm: 'RS256')

      expect(validates?(colliding)).to be false
    end

    it 'does not fall back to another issuer keys when the named one has no matching kid' do
      validates?(auth0_token(key: roadrunner_key, kid: roadrunner_kid, algorithm: 'RS512'))

      expect(a_request(:get, primary_jwks_url)).not_to have_been_made
    end
  end

  describe 'the algorithm comes from the issuer entry, not a literal (TKV.10)' do
    before { stub_every_issuer }

    # Signed by the right key, naming the right issuer, matching kid: the algorithm is the only
    # thing wrong with either of these.
    it 'rejects an RS512 token from an issuer configured RS256' do
      expect(validates?(auth0_token(algorithm: 'RS512'))).to be false
    end

    it 'rejects an RS256 token from an issuer configured RS512' do
      expect(validates?(roadrunner_token(algorithm: 'RS256'))).to be false
    end

    # The same entry, reconfigured, changes the answer -- which a hard-coded literal could not do.
    it 'accepts the algorithm the entry names, whatever that is' do
      TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry.merge(algorithm: 'RS512')]

      expect(validates?(auth0_token(algorithm: 'RS512'))).to be true
    end
  end

  describe 'the audience comes from the issuer entry' do
    before { stub_every_issuer }

    # Auth0's audience is not the primary issuer's, so TKV.06 passing at all already depends on
    # this. These pin it from both sides.
    it 'rejects an Auth0 token carrying the primary issuer audience' do
      expect(validates?(auth0_token(audience: primary_audience))).to be false
    end

    it 'rejects a roadrunner token carrying the Auth0 audience' do
      expect(validates?(roadrunner_token(audience: auth0_audience))).to be false
    end

    it 'accepts the audience the entry names' do
      TokenValidator::ValidatorConfig.additional_issuers = [auth0_entry.merge(audience: 'https://other.example.com')]

      expect(validates?(auth0_token(audience: 'https://other.example.com'))).to be true
    end
  end

  describe 'where the kid is written' do
    before { stub_every_issuer }

    # Auth0 puts it in the header, roadrunner in the payload. Both must be found.
    it 'finds a kid carried in the JOSE header' do
      expect(validates?(auth0_token)).to be true
    end

    it 'finds a kid carried in the payload' do
      expect(validates?(roadrunner_token)).to be true
    end

    # roadrunner's own token helper writes it to both places, with the same value.
    it 'accepts a token that carries the kid in both places' do
      both = JWT.encode(JWT.decode(roadrunner_token, nil, false).first, roadrunner_key, 'RS512', { kid: roadrunner_kid })

      expect(validates?(both)).to be true
    end

    it 'rejects a token naming a kid the issuer does not publish' do
      expect(validates?(roadrunner_token(kid: 'no-such-kid'))).to be false
    end

    # Neither provider emits a token whose two copies disagree, and that is exactly why the
    # precedence needs pinning: nothing else in this file can tell the two orderings apart. The
    # JOSE header is authoritative, per RFC 7515 -- swap the fallback around and both of these turn
    # red.
    it 'prefers the header kid when the two disagree' do
      header_right = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience).merge(kid: 'no-such-kid'),
                                roadrunner_key, 'RS512', { kid: roadrunner_kid })

      expect(validates?(header_right)).to be true
    end

    it 'does not fall back to the payload kid when the header names an unknown one' do
      header_wrong = JWT.encode(claims(issuer: primary_issuer, audience: primary_audience).merge(kid: roadrunner_kid),
                                roadrunner_key, 'RS512', { kid: 'no-such-kid' })

      expect(validates?(header_wrong)).to be false
    end
  end

  # An unknown kid triggers a retry, on the assumption that the issuer rotated its keys. Both kid
  # and iss come from a token nobody has authenticated yet, so what that retry is allowed to throw
  # away matters: a wholesale clear would let any rejected token flush every issuer's cache.
  describe 'the retry when a kid is not found' do
    before do
      with_cache
      stub_every_issuer
    end

    it 'refetches the keys of the issuer the token named' do
      validates?(auth0_token(kid: 'no-such-kid'))

      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
    end

    it 'leaves another issuer\'s cached keys alone' do
      validates?(roadrunner_token)
      validates?(auth0_token(kid: 'no-such-kid'))
      validates?(roadrunner_token)

      expect(a_request(:get, primary_jwks_url)).to have_been_made.once
    end
  end

  # If issuer selection ever went wrong, the verifier is the thing that catches it.
  #
  # There is no way to reach this by configuration -- selection matches `iss` exactly, so the entry
  # it returns always names the issuer the token claimed. Stubbing the lookup is the only way to
  # ask what happens when that stops being true, and it is worth asking: `verify_iss` and the
  # InvalidIssuerError rescue exist for precisely this case and are unreachable without it.
  describe 'if issuer selection ever returned the wrong entry' do
    before do
      stub_every_issuer
      allow(TokenValidator::ValidatorConfig).to receive(:issuer_config_for)
        .and_return(auth0_entry.merge(issuer_url: 'https://elsewhere.example.com/'))
    end

    it 'rejects a token the selected entry does not actually name' do
      expect(validates?(auth0_token)).to be false
    end
  end

  # The flags themselves, pinned directly. `verify_not_before` is the one no behavioural example in
  # this suite can reach -- no token here carries an `nbf` claim -- so without this, switching it
  # off would go unnoticed.
  describe 'what the verifier is told to check' do
    def options = described_class.new(auth0_token, expected_scopes).send(:verification_options, auth0_entry)

    it 'takes the algorithm, audience and issuer from the entry' do
      expect(options).to include(algorithm: 'RS256', aud: auth0_audience, iss: auth0_issuer)
    end

    it 'leaves every check switched on' do
      expect(options).to include(verify_aud: true, verify_iss: true, verify_expiration: true, verify_not_before: true)
    end
  end

  describe 'with no additional issuers configured' do
    before do
      TokenValidator::ValidatorConfig.additional_issuers = []
      stub_every_issuer
    end

    it 'still validates a primary-issuer token (REG.07)' do
      expect(validates?(roadrunner_token)).to be true
    end

    it 'rejects a token from an issuer that is no longer configured' do
      expect(validates?(auth0_token)).to be false
    end
  end
end
