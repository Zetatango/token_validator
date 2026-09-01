# frozen_string_literal: true

# Shared fixtures for the multi-issuer specs: the three issuers this library is configured to
# trust, the keys they sign with, and tokens built the way each provider builds them.
#
# Extracted so the verification specs (M1-03) and the rejection specs (M1-04) describe the same
# world. A rejection proven against a differently-shaped fixture proves less than it appears to.
module MultiIssuerTokens
  # RSA generation dominates the runtime of these files, and these keys carry no meaning beyond
  # being distinct from one another, so each is generated once and reused.
  KEYS = Hash.new { |keys, name| keys[name] = OpenSSL::PKey::RSA.new(2048) }

  # The three issuers, written out rather than derived from `ValidatorConfig.additional_issuers`.
  # An example generated from the collection it is testing deletes itself when that collection
  # shrinks, taking its own coverage with it and leaving the suite green -- the LEN-1069 finding,
  # and precisely the shape that would hide an issuer quietly losing its rejections.
  ISSUERS = [
    { name: 'the primary issuer', key: :roadrunner, algorithm: 'RS512', other_algorithm: 'RS256' },
    { name: 'the vanity issuer',  key: :roadrunner, algorithm: 'RS512', other_algorithm: 'RS256' },
    { name: 'Auth0',              key: :auth0,      algorithm: 'RS256', other_algorithm: 'RS512' }
  ].freeze

  # The two claims `expired?` compares against the clock, and so the two this library requires.
  TIME_CLAIMS = %i[iat exp].freeze

  # The cache namespace is derived from Rails.application's module name, which does not exist in
  # this suite. A named stand-in lets the real namespace code run rather than stubbing it out.
  Application = Class.new

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

  def roadrunner_key = KEYS[:roadrunner]
  def auth0_key = KEYS[:auth0]
  def roadrunner_kid = 'roadrunner-kid'
  def auth0_kid = 'auth0-kid'

  def expected_scopes = ['test:api']

  def vanity_entry
    { issuer_url: vanity_issuer, jwks_url: vanity_jwks_url, audience: primary_audience, algorithm: 'RS512' }
  end

  def auth0_entry
    { issuer_url: auth0_issuer, jwks_url: auth0_jwks_url, audience: auth0_audience, algorithm: 'RS256' }
  end

  def configure_issuers
    TokenValidator::ValidatorConfig.configure(issuer_url: primary_issuer, audience: primary_audience)
    TokenValidator::ValidatorConfig.additional_issuers = [vanity_entry, auth0_entry]
  end

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

  # Rails.cache is nil throughout this suite, so nothing is cached by default. Giving it a real
  # store is the only way to test what an eviction does and does not reach.
  def with_cache
    allow(Rails).to receive_messages(cache: cache, application: Application.new)
  end
end
