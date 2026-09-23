# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# PAR.01 — one user, two issuers, one normalized shape (M4-05, LEN-1225).
#
# HOW SOMEONE WOULD DEFEAT THESE EXAMPLES, written before the examples themselves, because a parity
# suite is unusually easy to make vacuous:
#
#   1. feed both issuers the SAME claim shape. The assertion then compares two copies of one object
#      and passes on a normalizer that does nothing at all. Each fixture here is built the way its
#      own issuer builds it, which is the only version of this test that means anything.
#   2. read the guid from +sub+. It WORKS on the golden pair, because a real imported user's subject
#      is `auth0|` + the guid -- so a passing golden pair proves nothing about it. The divergent
#      fixture exists for that one evasion.
#   3. normalize the primary issuer's claims too, changing behaviour for the cohort that is not
#      migrating. Asserted directly against the raw claims rather than against the other issuer.
#   4. fall back to the flat claim name when the namespaced one is absent. Generous, and a hole --
#      it would read a claim the issuer never asserted.
#   5. omit absent claims instead of answering nil, which turns `key?` into a question about the
#      issuer rather than the token.
RSpec.describe TokenValidator::ClaimNormalizer do
  include MultiIssuerTokens
  include NormalizedClaimTokens

  before do
    configure_namespaced_issuers
    stub_every_issuer
  end

  after { TokenValidator::ValidatorConfig.additional_issuers = [] }

  describe 'the golden pair' do
    # THE ACCEPTANCE CRITERION, and it is asserted as one object rather than field by field. A
    # per-field loop passes when a field is missing from both sides; comparing the whole hash does
    # not, and it also fails when a normalizer invents a key.
    it 'produces identical claims from either issuer for the same user' do
      from_roadrunner = normalized_through_service(roadrunner_golden_token)
      from_auth0 = normalized_through_service(auth0_golden_token)

      expect(from_auth0).to eq(from_roadrunner)
    end

    # TWO COPIES OF NOTHING ARE ALSO EQUAL, so the pair above would pass on a normalizer that read
    # neither issuer. These two say the values actually arrived, and they say it by comparing
    # against the USER rather than against the other issuer -- `GOLDEN_USER` holds exactly the
    # claims in `CLAIMS`, so this is the whole contract in one assertion and it fails on an invented
    # key, a dropped key or a crossed-over pair.
    it 'resolves the auth0 token to the user it describes' do
      expect(normalized_through_service(auth0_golden_token)).to eq(golden_user)
    end

    it 'resolves the primary issuer token to the same user' do
      expect(normalized_through_service(roadrunner_golden_token)).to eq(golden_user)
    end

    # +false+ IS A VALUE, NOT AN ABSENCE, and the pair would pass if a normalizer turned it into
    # nil on both sides. An opt-out recorded as nil reads as "never asked", which is a different
    # fact about a customer than "asked and declined".
    it 'preserves a false preference as false on both paths' do
      expect(normalized_through_service(roadrunner_golden_token)[:insights_preference_sms]).to be false
      expect(normalized_through_service(auth0_golden_token)[:insights_preference_sms]).to be false
      expect(normalized_through_service(auth0_golden_token)[:insights_preference_email]).to be true
    end
  end

  # EVASION 2. The example that matters most, because the failure it prevents is a change of
  # AUTHORITY rather than a missing value -- consumers in this estate gate on the shape of the
  # subject, and an unexpected shape does not always make them fail. Kept deliberately unspecific:
  # this repository is public and the consumer-side behaviour is not fixed yet.
  describe 'the user guid, when the subject does not contain it' do
    it 'comes from the claim rather than the subject' do
      normalized = normalized_through_service(
        JWT.encode(divergent_auth0_claims_for, auth0_key, 'RS256', { kid: auth0_kid })
      )

      expect(normalized[:user_guid]).to eq(golden_user[:user_guid])
    end

    it 'never answers with the raw auth0 subject' do
      token = JWT.encode(divergent_auth0_claims_for, auth0_key, 'RS256', { kid: auth0_kid })

      expect(normalized_through_service(token)[:user_guid]).not_to start_with('auth0|')
    end
  end

  # EVASION 3. The primary issuer's cohort is not migrating, and this says so against the claims
  # themselves rather than against the other issuer -- a mistake applied to both paths equally
  # would satisfy the golden pair.
  describe 'the primary issuer' do
    it 'reads its claims flat, exactly as they sit in the token' do
      normalized = normalized_through_service(roadrunner_golden_token)
      expected = golden_user.except(:user_guid)

      expected.each do |claim, value|
        expect(normalized[claim]).to eq(value)
      end
    end

    it 'takes the user guid from the subject, which is the only place it is' do
      expect(normalized_through_service(roadrunner_golden_token)[:user_guid])
        .to eq(golden_user[:user_guid])
    end

    it 'is not treated as namespaced' do
      service = TokenValidator::TokenService.new(roadrunner_golden_token, expected_scopes)
      expect(service.valid_access_token?).to be true

      expect(service.namespaced_claims?).to be false
    end
  end

  # EVASION 4. A top-level claim on a namespaced token is not something the issuer said. Auth0 drops
  # unnamespaced custom claims from what IT emits, so anything sitting at the top level of such a
  # token got there another way and must not be read.
  describe 'a namespaced token carrying an unnamespaced claim' do
    it 'ignores the top-level value rather than falling back to it' do
      payload = auth0_claims_for.merge(roles: %w[admin], properties: { 'role' => 'partner_admin' })
      payload.delete("#{claim_namespace}roles")

      normalized = normalized_through_service(JWT.encode(payload, auth0_key, 'RS256', { kid: auth0_kid }))

      expect(normalized[:roles]).to be_nil
      expect(normalized[:properties]).to eq(golden_user[:properties])
    end

    it 'reports itself as namespaced' do
      service = TokenValidator::TokenService.new(auth0_golden_token, expected_scopes)
      expect(service.valid_access_token?).to be true

      expect(service.namespaced_claims?).to be true
    end
  end

  # EVASION 5.
  describe 'a claim the token did not carry' do
    let(:from_auth0) do
      described_class.new({ "#{claim_namespace}user_guid" => 'u_sparse' }.with_indifferent_access,
                          auth0_namespaced_entry).normalized
    end

    let(:from_roadrunner) { described_class.new({ sub: 'u_sparse' }.with_indifferent_access).normalized }

    it 'is present and nil, identically on both issuers' do
      expect(from_auth0).to eq(from_roadrunner)
    end

    it 'keeps a key for every claim, so `key?` asks about the token and not the issuer' do
      expect(from_auth0.keys).to eq(described_class::CLAIMS)
      expect(from_auth0.except(:user_guid).values.uniq).to eq([nil])
    end
  end

  # The unit-level edges, driven directly because no real issuer emits them and a token carrying
  # them would not get past +valid_structure?+ anyway. They are here because the normalizer is
  # public API now: a consumer can hand it anything.
  describe 'defensively, given a payload nobody would issue' do
    it 'answers nils rather than raising, for a payload that is not a hash' do
      [nil, [], 'a string', 7].each do |payload|
        expect { described_class.new(payload).normalized }.not_to raise_error
        expect(described_class.new(payload).normalized.values.uniq).to eq([nil])
      end
    end

    it 'treats a nil issuer entry as the primary issuer' do
      normalized = described_class.new({ sub: 'u_1', enabled: true }.with_indifferent_access, nil).normalized

      expect(normalized[:user_guid]).to eq('u_1')
      expect(normalized[:enabled]).to be true
    end

    # An entry without the key is the primary issuer's shape, which is the whole reason the key is
    # optional rather than defaulted to nil.
    it 'treats an entry with no claim_namespace as unprefixed' do
      normalizer = described_class.new({ sub: 'u_1' }.with_indifferent_access, auth0_entry)

      expect(normalizer.namespaced?).to be false
      expect(normalizer.normalized[:user_guid]).to eq('u_1')
    end
  end
end
