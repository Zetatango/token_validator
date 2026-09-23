# frozen_string_literal: true

# The golden pair: one user, described by each issuer the way that issuer describes it (M4-05,
# LEN-1225).
#
# SEPARATE FROM +MultiIssuerTokens+ RATHER THAN BOLTED ONTO IT, and +auth0_entry+ in particular is
# left alone. That entry is compared as a whole by the configuration specs, and its own comment
# notes that an entry omitting an optional key must stay byte-identical to one written before the
# key existed -- adding +claim_namespace+ to it would quietly make every one of those examples
# assert the new shape instead of the old one. The namespaced entry is a second fixture.
#
# THE NAMESPACE HERE IS FICTIONAL, and that is the point of the design rather than a detail of the
# test. The namespace is per-issuer configuration precisely so that no estate's real claim schema
# is written into this public repository; a fixture that used the real one would undo that.
module NormalizedClaimTokens
  CLAIM_NAMESPACE = 'https://claims.example.com/'

  # ONE USER, and every value distinct from every other so that a normalizer which crosses two
  # claims over produces a visible failure rather than a passing swap. `applicant` and
  # `primary_partner` are the pair most at risk -- both are guids of different kinds -- so they are
  # deliberately unalike.
  #
  # +properties+ CARRIES THE PROFILE GUID under `profile`, which is where the profile-scoped shape
  # puts it, and a `lead`. A real merchant_new profile carries no `merchant` key at all, so this one
  # does not either: a fixture that filled in every possible key would let a normalizer that assumes
  # presence pass.
  GOLDEN_USER = {
    user_guid: 'u_14N9EEqXA4rHxBgo',
    enabled: true,
    properties: {
      'profile' => 'prof_m2pkoPMkG5S6E1Zb',
      'role' => 'merchant_new',
      'partner' => 'p_7J9FJv6qpnG8Q8E2',
      'lead' => 'lead_9ScbDTB7Pd7pn6ZD'
    },
    profiles: [
      { 'guid' => 'prof_m2pkoPMkG5S6E1Zb', 'properties' => { 'role' => 'merchant_new' } },
      { 'guid' => 'prof_SECONDoVRzJ8Jn', 'properties' => { 'role' => 'merchant_admin' } }
    ],
    roles: %w[underwriter1 treasury],
    primary_partner: 'p_7J9FJv6qpnG8Q8E2',
    preferred_language: 'fr',
    applicant: 'app_HLD8shTz9mAMKYvE',
    product_preference: 'LOC',
    insights_preference_email: true,
    insights_preference_sms: false
  }.freeze

  def claim_namespace = CLAIM_NAMESPACE

  def golden_user = GOLDEN_USER

  # The Auth0 entry, plus the namespace its claims are prefixed with.
  def auth0_namespaced_entry
    auth0_entry.merge(claim_namespace: claim_namespace)
  end

  def configure_namespaced_issuers
    TokenValidator::ValidatorConfig.configure(issuer_url: primary_issuer, audience: primary_audience)
    TokenValidator::ValidatorConfig.additional_issuers = [vanity_entry, auth0_namespaced_entry]
  end

  # THE PRIMARY ISSUER'S SHAPE: custom claims unprefixed at the top level, and NO +user_guid+ claim
  # -- the guid is the subject. Leaving it out is what makes the subject fallback load-bearing
  # rather than decorative; a fixture that emitted both would let a normalizer which ignores +sub+
  # pass this pair.
  def roadrunner_claims_for(user = golden_user)
    flat = user.except(:user_guid)
    claims(issuer: primary_issuer, audience: primary_audience)
      .merge(flat)
      .merge(sub: user[:user_guid], kid: roadrunner_kid)
  end

  # AUTH0'S SHAPE: every custom claim under the namespace, and a subject that is Auth0's own.
  #
  # +sub+ EMBEDS THE GUID (`auth0|u_...`) because that is what a real imported user looks like. It
  # is the trap worth reproducing: string surgery on the subject yields the right answer here, so a
  # normalizer that does that passes the golden pair. `divergent_auth0_claims_for` is the fixture
  # that catches it.
  def auth0_claims_for(user = golden_user, subject: nil)
    namespaced = user.transform_keys { |key| "#{claim_namespace}#{key}" }
    claims(issuer: auth0_issuer, audience: auth0_audience)
      .merge(namespaced)
      .merge(sub: subject || "auth0|#{user[:user_guid]}")
  end

  # The same Auth0 token with a subject that does NOT contain the guid, so the claim is the only
  # place the right answer exists.
  def divergent_auth0_claims_for(user = golden_user)
    auth0_claims_for(user, subject: 'auth0|655f7c3a9b1e4d8f0a2c6e11')
  end

  def roadrunner_golden_token(user = golden_user)
    JWT.encode(roadrunner_claims_for(user), roadrunner_key, 'RS512')
  end

  def auth0_golden_token(user = golden_user)
    JWT.encode(auth0_claims_for(user), auth0_key, 'RS256', { kid: auth0_kid })
  end

  # Normalizing through +TokenService+ rather than by constructing the normalizer directly, so the
  # issuer resolution under test is the real one -- the entry the signature was verified against.
  def normalized_through_service(token)
    service = TokenValidator::TokenService.new(token, expected_scopes)
    expect(service.valid_access_token?).to be true
    service.normalized_claims
  end
end
