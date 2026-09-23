# frozen_string_literal: true

# One shape for a token's custom claims, whichever issuer emitted them (M4-05, LEN-1225).
#
# THE PROBLEM THIS SOLVES IS NOT COSMETIC. The estate's issuers carry the same information under
# different claim names: the primary issuer emits custom claims unprefixed at the top level, and
# Auth0 requires every custom claim to sit under a namespace. A consumer reading +properties+
# directly gets the value from one issuer and +nil+ from the other, and +nil+ is indistinguishable
# from "this token carried nothing" -- so the branch goes dark with no error, no log line and a 200
# response. That is the failure +granted_scopes+ was made public to prevent for the permission
# claims (LEN-1159); this is the same failure for everything else a token says.
#
# THE ISSUER IS DECIDED BY +iss+, NEVER BY THE CALL PATH. +TokenService+ hands this the entry that
# +ValidatorConfig.issuer_config_for+ resolved -- the same entry whose key and algorithm the
# signature was verified against. Re-deriving the issuer here, or letting the caller declare it,
# would allow this to normalize as one issuer a token that was verified as another. That is the
# specific hazard a copy of this logic outside the gem could not be tested out of, and it is the
# reason this class lives here.
class TokenValidator::ClaimNormalizer
  # WHAT A CONSUMER READS, listed once so the two issuers cannot drift apart claim by claim.
  #
  # These are the flat names -- the primary issuer's own spelling, because that is the shape every
  # consumer already reads and the one this exists to preserve. An Auth0 token's claim for each is
  # the issuer's +claim_namespace+ followed by the same name.
  #
  # +insights_preference_email+ and +insights_preference_sms+ are spelled out separately, and that
  # is the contract rather than an oversight: the primary issuer emits the two of them and never a
  # combined +insights_preference+. A consumer reading the singular gets nil from both issuers
  # today, which is parity, and "fixing" it here would invent a claim neither issuer sends.
  CLAIMS = %i[
    user_guid
    enabled
    properties
    profiles
    roles
    primary_partner
    preferred_language
    applicant
    product_preference
    insights_preference_email
    insights_preference_sms
  ].freeze

  # THE ONE CLAIM WHOSE SOURCES GENUINELY DIFFER, rather than differing only by prefix.
  #
  # The primary issuer puts the user guid in +sub+. Auth0 cannot: its subject is its own
  # (`auth0|...`), so the guid travels as a claim and +sub+ holds something else entirely.
  #
  # This matters more than the other ten together, and the reason is worth stating without the
  # specifics: consumers in this estate gate behaviour on the *shape* of the subject, and a subject
  # in an unexpected shape does not always make them fail. Some fall through to a different
  # credential instead. So getting this claim wrong is not a missing value, it is a change of
  # AUTHORITY, and it is silent.
  #
  # Any parity fixture that checks the +properties+ family and not this one passes while leaving
  # that in place, which is why the spec has a dedicated example for it rather than trusting the
  # golden pair. (Deliberately vague about which consumers and which fallback: this repository is
  # public and that behaviour is not fixed yet.)
  SUBJECT_CLAIM = 'sub'

  # +issuer_entry+ is the resolved configuration for whichever issuer signed the token, or +nil+ for
  # the primary issuer, which has no entry in +additional_issuers+. A +nil+ entry and an entry
  # without +claim_namespace+ mean the same thing -- unprefixed claims -- and both are the primary
  # issuer's shape.
  def initialize(decoded_jwt, issuer_entry = nil)
    @decoded_jwt = decoded_jwt || {}
    @issuer_entry = issuer_entry || {}
  end

  # The flat hash, with a key for every entry in +CLAIMS+.
  #
  # EVERY KEY IS ALWAYS PRESENT, and a claim the token did not carry is +nil+. The alternative --
  # omitting absent claims -- makes `normalized.key?(:properties)` a question about the issuer
  # rather than about the token, which is exactly the issuer-specific reasoning this removes. A
  # consumer asks for a value and gets one or gets nil.
  #
  # SYMBOL KEYS, matching +CLAIMS+, regardless of how the decoded payload is keyed. The payload
  # arrives from +TokenService#decoded_jwt+ as a +HashWithIndifferentAccess+, but this is also
  # called with a plain Hash in specs and by consumers assembling a token by hand, so reads below
  # try both forms rather than trusting one.
  def normalized
    CLAIMS.to_h { |claim| [claim, value_for(claim)] }
  end

  # Whether this issuer's claims are namespaced. Public because it is the honest answer to "did
  # this token come from the namespaced issuer", which consumers otherwise reconstruct by sniffing
  # +sub+ for a pipe -- a guess that breaks on the first issuer whose subjects are shaped
  # differently.
  def namespaced?
    namespace.present?
  end

  private

  def namespace
    @namespace ||= claim(@issuer_entry, :claim_namespace)
  end

  # +user_guid+ IS RESOLVED FROM ITS CLAIM FIRST ON EITHER ISSUER, and falls back to +sub+ only
  # when no claim carried it.
  #
  # The order is deliberate and it is not symmetrical with the fallback's availability. Reading
  # +sub+ first would work today for the primary issuer and would also "work" for an Auth0 token
  # whose subject happens to embed the guid -- an imported user's subject is `auth0|u_...`, so
  # string surgery on it looks correct and produces the right answer for exactly as long as the
  # import format holds. Preferring the claim means the contract decides and the subject is only
  # ever a fallback for an issuer that has no such claim.
  def value_for(claim)
    return user_guid if claim == :user_guid

    read(claim)
  end

  def user_guid
    read(:user_guid) || claim(@decoded_jwt, SUBJECT_CLAIM)
  end

  # Namespaced issuers are read ONLY under their namespace, never with a fallback to the flat name.
  #
  # A fallback would look generous and would be a hole: a token from the namespaced issuer that
  # carried a top-level +roles+ -- which any client can put in a token it mints for itself, and
  # which Auth0 silently drops from its *own* claims but not from a hand-assembled payload -- would
  # be read as though the issuer had asserted it. Claims are only trustworthy where the issuer puts
  # them, so that is the only place this looks.
  def read(claim)
    return claim(@decoded_jwt, "#{namespace}#{claim}") if namespaced?

    claim(@decoded_jwt, claim)
  end

  def claim(source, key)
    return nil unless source.respond_to?(:[])

    source[key.to_sym] || source[key.to_s]
  rescue TypeError, NoMethodError
    # A payload that decoded to something indexable-but-not-by-key (an Array) raises rather than
    # answering nil. `TokenService` already refuses those at `valid_structure?`, so reaching this is
    # a caller that skipped verification -- answer nil rather than raise a different error than the
    # one they would have got.
    nil
  end
end
