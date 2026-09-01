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
  # Distinct from JwtFormatException so that "someone is presenting the wrong algorithm for this
  # issuer" can be told apart from "garbage arrived". The jwt gem raises both as DecodeError, which
  # flattened the two into one message and left alerting unable to distinguish them.
  class InvalidAlgorithmException < TokenServiceException; end
  class InvalidSignatureKeyException < TokenServiceException; end
  class InvalidAudienceException < TokenServiceException; end
  class ExpiredJwtException < TokenServiceException; end
  class MissingAccessTokenField < TokenServiceException; end
  class ReplayedJwtException < TokenServiceException; end
  class InvalidScope < TokenServiceException; end

  # The claims this library compares against the clock, and the wording each is reported under.
  # +nbf+ is not required, but is type-checked when present for the same reason as these.
  REQUIRED_TIME_CLAIMS = { 'iat' => 'issued at', 'exp' => 'expiry' }.freeze

  # The three shapes a token can express its permissions in, all of them read and combined:
  #
  # - +scopes+ -- a list, which is what the primary issuer has always emitted
  # - +scope+  -- a space-separated string, the OAuth 2.0 spelling (RFC 6749 section 3.3) Auth0 uses
  # - +permissions+ -- a list, which Auth0 adds when role-based access control is enabled
  #
  # A token may carry more than one, and they are unioned rather than one winning: an Auth0 tenant
  # with RBAC on emits +scope+ and +permissions+ together, and they do not necessarily agree.
  PERMISSION_CLAIMS = %w[scopes scope permissions].freeze

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
    valid_time_claims? && valid_signature? && valid_contents? && valid_scope?
  end

  # +iat+ and +exp+ must be numbers, and +nbf+ must be one when it is there at all.
  #
  # Checked *before* the signature, which is deliberate and is the only placement that works: the
  # verifier itself reads +exp+ and +nbf+, and on a claim of the wrong type it raises NoMethodError
  # from inside the gem -- escaping +valid_access_token?+, whose contract is to answer true or
  # false, exactly as the ArgumentError from comparing nil to the clock used to. A check that ran
  # after verification could not reach that case at all.
  #
  # Reading unverified claims in order to *type-check* them decides nothing and grants nothing. The
  # token still faces every check below, and one that fails here would have failed there.
  def valid_time_claims?
    REQUIRED_TIME_CLAIMS.each do |claim, description|
      raise MissingAccessTokenField, "Missing or invalid #{description}" unless decoded_jwt[claim].is_a?(Numeric)
    end

    raise MissingAccessTokenField, 'Invalid not before' if decoded_jwt.key?('nbf') && !decoded_jwt['nbf'].is_a?(Numeric)

    true
  rescue JWT::DecodeError
    # Too malformed to read a claim from is simply malformed, and is reported as it always was.
    raise JwtFormatException, 'Invalid token'
  end

  def valid_scope?
    granted = granted_scopes

    # Carrying none of the three claims is what "missing scopes" has always meant, and it still
    # fails even when nothing was required -- which is the behaviour every existing spec pins.
    raise InvalidScope, 'Missing scopes' if granted.nil?
    return true if @expected_scopes.blank?

    raise InvalidScope, "Missing scope: require at least one of #{@expected_scopes}" unless granted.intersect?(@expected_scopes)

    true
  end

  # Everything the token grants, from whichever of the three claims it carries, or nil when it
  # carries none of them.
  #
  # Presence is decided by the claim being *there*, not by it holding anything: a token with an
  # empty list has said it has no permissions, which is a different statement from saying nothing.
  def granted_scopes
    present = PERMISSION_CLAIMS.select { |claim| decoded_jwt.key?(claim) }
    return nil if present.empty?

    present.flat_map { |claim| scope_values(decoded_jwt[claim]) }.uniq
  end

  # A list is already a list of scopes; a string is split on whitespace, which is how OAuth 2.0
  # spells one.
  #
  # Splitting is the point, not a formality. The check this replaced asked the claim +include?+,
  # and +include?+ on a String matches a *substring* -- so reading the +scope+ string without
  # splitting it would let a token carrying +superadmin:write+ satisfy a required +admin+. Anything
  # that is neither shape grants nothing, rather than raising: a claim we do not understand is not
  # one to act on.
  def scope_values(value)
    return value if value.is_a?(Array)
    return value.split if value.is_a?(String)

    []
  end

  def valid_contents?
    raise MissingAccessTokenField, 'Missing subject' unless decoded_jwt.key?('sub')

    true
  end

  def expired?
    # Compared as floats because RFC 7519 permits a fractional NumericDate, and an integer clock
    # against a fractional +iat+ reads a token issued this very second as issued in the future.
    expired = Time.now.to_f < decoded_jwt['iat'] || Time.now.to_f > decoded_jwt['exp']

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
  rescue JWT::IncorrectAlgorithm
    # Ahead of the DecodeError rescue below, which it is a subclass of.
    raise InvalidAlgorithmException, algorithm_mismatch_message(entry)
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

  # Names the algorithm the issuer is configured for, because that is ours to name and it is what
  # an operator needs in order to act.
  #
  # The algorithm the *token* names is attacker-controlled text on its way into a log, so it is
  # echoed only when it is one of +PERMITTED_ISSUER_ALGORITHMS+ -- in which case the value printed
  # is one of our own constants rather than the token's bytes. A token claiming +HS256+, or an
  # +alg+ carrying newlines to forge a log line, is refused with the shorter message instead.
  #
  # Every reachable +IncorrectAlgorithm+ really is about the algorithm: the gem raises it when the
  # token names one that is not allowed here, and when it names none at all.
  def algorithm_mismatch_message(entry)
    claimed = jwt_header['alg']
    configured = "issuer is configured for #{entry[:algorithm]}"

    return "Invalid algorithm: #{configured}" unless TokenValidator::ValidatorConfig::PERMITTED_ISSUER_ALGORITHMS.include?(claimed)

    "Invalid algorithm: token names #{claimed}, #{configured}"
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
