# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# M1-05 (LEN-961): a token's permissions are read from whichever of three claims it carries, and
# from all of them at once when it carries more than one.
#
# The primary issuer emits a `scopes` list. Auth0 emits a space-separated `scope` string, and adds a
# `permissions` list when role-based access control is on -- so an Auth0 tenant with RBAC emits two
# of the three, and they do not necessarily agree.
RSpec.describe TokenValidator::TokenService do
  include MultiIssuerTokens

  before do
    configure_issuers
    stub_every_issuer

    described_class.clear
  end

  after { TokenValidator::ValidatorConfig.additional_issuers = [] }

  def primary_issuer_shape = MultiIssuerTokens::ISSUERS.first
  def auth0_shape = MultiIssuerTokens::ISSUERS.last

  # Builds a token carrying exactly the permission claims given, and none of the others: the
  # default `scopes` claim is removed unless it is one of them.
  def token_granting(issuer: primary_issuer_shape, **permission_claims)
    token_from(issuer, claim_overrides: permission_claims, delete: [:scopes] - permission_claims.keys)
  end

  def granted?(token, required = ['test:api'])
    described_class.new(token, required).valid_access_token?
  end

  describe 'each format on its own' do
    it 'honours the list claim the primary issuer emits (TKV.13)' do
      expect(granted?(token_granting(scopes: %w[test:api other:thing]))).to be true
    end

    it 'honours the space-separated string claim (TKV.14)' do
      expect(granted?(token_granting(scope: 'other:thing test:api'))).to be true
    end

    it 'honours the role-based-access-control list claim (TKV.15)' do
      expect(granted?(token_granting(permissions: %w[other:thing test:api]))).to be true
    end

    # The claim shapes are a property of the token, not of who issued it, and nothing in the code
    # ties them together -- but Auth0 is the reason the last two exist, so it is worth one end to
    # end.
    it 'honours an Auth0 token carrying scope and permissions together' do
      token = token_granting(issuer: auth0_shape, scope: 'openid profile', permissions: %w[test:api])

      expect(granted?(token)).to be true
    end
  end

  describe 'more than one format at once' do
    it 'uses the union when all three are present (TKV.16)' do
      token = token_granting(scopes: %w[first:one], scope: 'second:one', permissions: %w[third:one])

      expect(granted?(token, %w[third:one])).to be true
      expect(granted?(token, %w[second:one])).to be true
      expect(granted?(token, %w[first:one])).to be true
    end

    # The failure this guards against is one claim silently winning: whichever is read first would
    # satisfy its own example while hiding the others.
    it 'does not let the first claim present decide the answer' do
      token = token_granting(scopes: %w[first:one], permissions: %w[third:one])

      expect(granted?(token, %w[third:one])).to be true
    end

    it 'still refuses a permission none of the three carries' do
      token = token_granting(scopes: %w[first:one], scope: 'second:one', permissions: %w[third:one])

      expect(rejection_for(token, %w[fourth:one])).to be_a(TokenValidator::TokenService::InvalidScope)
        .and have_attributes(message: 'Missing scope: require at least one of ["fourth:one"]')
    end
  end

  # `include?` on a String matches a substring, and the check this replaced asked the claim
  # `include?` directly. Reading the space-separated claim without splitting it would therefore let
  # a token satisfy a permission it does not hold -- and `scope` is a string by definition, so this
  # is the shape the issue's naive implementation has.
  describe 'a scope is a whole scope, never part of one' do
    it 'does not let superadmin:write satisfy a required admin' do
      token = token_granting(scope: 'superadmin:write')

      expect(granted?(token, %w[admin])).to be false
    end

    it 'does not let a longer scope satisfy a prefix of itself' do
      token = token_granting(scope: 'test:apikey')

      expect(granted?(token, %w[test:api])).to be false
    end

    # The same trap through the original claim, which nothing stops an issuer sending as a string.
    it 'splits the list claim too, when it arrives as a string' do
      token = token_granting(scopes: 'superadmin:write')

      expect(granted?(token, %w[admin])).to be false
      expect(granted?(token, %w[superadmin:write])).to be true
    end
  end

  describe 'when the token grants nothing' do
    it 'refuses one carrying none of the three claims' do
      token = token_granting

      expect(rejection_for(token)).to be_a(TokenValidator::TokenService::InvalidScope)
        .and have_attributes(message: 'Missing scopes')
    end

    # Carrying none of them fails even when nothing was required, which is what this library has
    # always done -- an unchanged behaviour that is easy to lose while rewriting the check around it.
    it 'refuses one carrying none of them even when no permission was required' do
      expect(rejection_for(token_granting, [])).to be_a(TokenValidator::TokenService::InvalidScope)
        .and have_attributes(message: 'Missing scopes')
    end

    # Present-but-empty is a different statement from absent: the token said it holds nothing.
    it 'distinguishes an empty claim from an absent one' do
      expect(rejection_for(token_granting(scope: ''))).to have_attributes(message: 'Missing scope: require at least one of ["test:api"]')
      expect(rejection_for(token_granting(permissions: []))).to have_attributes(message: 'Missing scope: require at least one of ["test:api"]')
    end

    it 'accepts an empty claim when nothing was required' do
      expect(granted?(token_granting(permissions: []), [])).to be true
    end

    # A claim of a shape this library does not understand grants nothing, rather than raising a
    # TypeError out of a method whose contract is to answer true or false.
    it 'grants nothing for a claim that is neither a list nor a string' do
      expect { granted?(token_granting(scope: 42)) }.not_to raise_error
      expect(rejection_for(token_granting(scope: 42))).to be_a(TokenValidator::TokenService::InvalidScope)
    end
  end
end
