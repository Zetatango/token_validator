# frozen_string_literal: true

class TokenValidator::TokenService
  class TokenServiceException < RuntimeError
    attr_reader :message

    def initialize(message)
      super
      @message = message
    end
  end

  class JwtFormatException < TokenServiceException; end
  class InvalidIssuerException < TokenServiceException; end
  class InvalidSignatureException < TokenServiceException; end
  class InvalidSignatureKeyException < TokenServiceException; end
  class InvalidAudienceException < TokenServiceException; end
  class ExpiredJwtException < TokenServiceException; end
  class MissingAccessTokenField < TokenServiceException; end
  class ReplayedJwtException < TokenServiceException; end
  class InvalidScope < TokenServiceException; end

  def self.clear
    TokenValidator::OauthTokenService.instance.clear
  end

  def initialize(access_token, expected_scopes)
    @access_token = access_token
    @expected_scopes = expected_scopes
  end

  def decoded_jwt
    @decoded_jwt = JWT.decode(@access_token, nil, false)&.first&.with_indifferent_access
  end

  def valid_access_token?
    valid_structure? && !expired?
  rescue TokenServiceException => e
    TokenValidator::ValidatorConfig.logger.error "Invalid access token: #{e.message}"
    false
  end

  private

  def valid_structure?
    valid_signature? && valid_contents? && valid_scope?
  end

  def valid_scope?
    raise InvalidScope, 'Missing scopes' unless decoded_jwt.key?('scopes')
    return true if @expected_scopes.blank?

    valid = false
    @expected_scopes.each do |scope|
      valid ||= decoded_jwt['scopes'].include? scope
    end

    raise InvalidScope, "Missing scope: require at least one of #{@expected_scopes}" unless valid

    true
  end

  # +iat+ and +exp+ are checked for presence here, beside +sub+, because +expired?+ compares both
  # against the clock. Absent, they used to reach that comparison as nil and raise ArgumentError --
  # an exception escaping +valid_access_token?+, whose whole contract is to answer true or false.
  # A token that does not say when it was issued or when it stops being valid cannot be shown to be
  # current, so it is refused rather than assumed current.
  def valid_contents?
    raise MissingAccessTokenField, 'Missing subject' unless decoded_jwt.key?('sub')
    raise MissingAccessTokenField, 'Missing issued at' unless decoded_jwt.key?('iat')
    raise MissingAccessTokenField, 'Missing expiry' unless decoded_jwt.key?('exp')

    true
  end

  def expired?
    expired = Time.now.to_i < decoded_jwt['iat'] || Time.now.to_i > decoded_jwt['exp']

    raise ExpiredJwtException, 'Access token is expired' if expired

    false
  end

  def valid_signature?
    entry = issuer_entry

    # Nothing this library trusts issued this token, so there is nothing to hold it to -- no key, no
    # algorithm, no audience. Rejected before any of them is reached, which also means an untrusted
    # claim can no longer make this process fetch a JWKS. M1-04 covers this path in depth.
    raise InvalidIssuerException, 'Invalid issuer' if entry.nil?

    jwk = find_jwk(entry)

    raise InvalidSignatureKeyException, 'Could not match token\'s kid with jwks from issuer' if jwk.nil?

    verified = JWT.decode(@access_token, jwk.to_key, true, verification_options(entry))[0]

    raise InvalidSignatureException, 'Invalid signature' unless verified

    true
  rescue JWT::ExpiredSignature
    raise ExpiredJwtException, 'Access token is expired'
  rescue JWT::InvalidIssuerError
    raise InvalidIssuerException, 'Invalid issuer'
  rescue JWT::InvalidAudError
    raise InvalidAudienceException, 'Invalid audience'
  rescue JWT::DecodeError
    raise JwtFormatException, 'Invalid token'
  end

  # The trusted issuer entry matching the token's +iss+ claim, or nil when this library trusts no
  # such issuer.
  #
  # +iss+ is read from a token whose signature has not been verified yet. That is unavoidable --
  # which key to verify with is precisely what this decides -- and it is safe only because the claim
  # is used to *select* the configuration the token is then held to, never to grant anything. A
  # token that names an issuer is thereby held to that issuer's key, algorithm and audience; naming
  # one that did not sign it only makes it fail sooner.
  def issuer_entry
    TokenValidator::ValidatorConfig.issuer_config_for(decoded_jwt['iss'])
  end

  # The three values that used to belong to the single provider -- +RS512+ as a literal, and the
  # audience and issuer URL read from +config+ -- now come from the entry of whichever issuer signed
  # the token. An Auth0 token failed all three of them before this.
  #
  # +algorithm+ is a single value per issuer, not a list, and LEN-1069 has already constrained it to
  # asymmetric algorithms at configuration time, so no shared-secret algorithm can arrive here.
  def verification_options(entry)
    {
      algorithm: entry[:algorithm],
      verify_expiration: true,  # Verify token expiration (exp claim)
      verify_not_before: true,  # Verify not before (nbf claim)
      aud: entry[:audience],
      verify_aud: true, # Verify audience (aud claim)
      # Checked again although the entry was found *by* this claim: it is what makes selecting on an
      # unverified claim safe. The token is verified against the issuer it named, by a verifier that
      # does not take this class's word for which entry it chose.
      iss: entry[:issuer_url],
      verify_iss: true # Verify issuer (iss claim)
    }
  end

  # A +kid+ this issuer has not published usually means it rotated its keys, so forget what we
  # cached for *that issuer* and look once more.
  #
  # Scoped rather than a full +clear+ on purpose: +kid+ and +iss+ both come from an unauthenticated
  # token, so a wholesale flush here would let any rejected token evict every other issuer's keys
  # and machine tokens and force a round of refetches.
  def find_jwk(entry)
    jwk = search_jwks(entry)
    if jwk.nil?
      TokenValidator::OauthTokenService.instance.clear_signing_key(entry[:issuer_url])
      jwk = search_jwks(entry)
    end
    jwk
  end

  # Asks for this issuer's keys by name rather than for the default set. For the primary issuer that
  # resolves to the address it has always resolved to, so its path is unchanged; for any other, the
  # per-issuer cache from M1-02 is what stops one issuer's keys being handed back for another's
  # token.
  def search_jwks(entry)
    jwks = TokenValidator::OauthTokenService.instance.signing_key(entry[:issuer_url])
    return nil if jwks.blank?

    kid = token_kid

    jwks.each do |key|
      return key if key['kid'] == kid
    end

    nil
  end

  # The +kid+ the token names: from its header when it carries one there, from its payload
  # otherwise.
  #
  # The two providers disagree about where it belongs. Auth0 puts it in the JOSE header, which is
  # what JWS specifies; the primary issuer has always written it into the payload instead
  # (roadrunner's +Doorkeeper::JWT.token_payload+ sets +kid+ as a claim). Reading the header first
  # and falling back to the payload is what lets an Auth0 token be matched to a key at all, and
  # changes nothing for a token issued today -- roadrunner either omits the header +kid+ or sets it
  # to the same value as the claim.
  #
  # Neither copy is verified here, and neither has to be. +kid+ only chooses which of *this
  # issuer's* published keys to try; a token naming the wrong one fails the signature check that
  # follows.
  def token_kid
    jwt_header['kid'].presence || decoded_jwt['kid']
  end

  def jwt_header
    JWT.decode(@access_token, nil, false).last.with_indifferent_access
  end
end
