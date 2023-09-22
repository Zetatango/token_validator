# frozen_string_literal: true

class TokenValidator::TokenService
  class TokenServiceException < RuntimeError
    attr_reader :message

    def initialize(message)
      super(message)
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
  rescue JWT::DecodeError => e
    TokenValidator::ValidatorConfig.logger.error "Invalid JWT format: #{e.message}"
    false
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

  def valid_contents?
    raise MissingAccessTokenField, 'Missing subject' unless decoded_jwt.key?('sub')

    true
  end

  def expired?
    expired = Time.now.to_i < decoded_jwt['iat'] || Time.now.to_i > decoded_jwt['exp']

    raise ExpiredJwtException, 'Access token is expired' if expired

    false
  end

  def valid_audience?
    raise InvalidAudienceException, 'Invalid audience' unless decoded_jwt['aud'].include? TokenValidator::ValidatorConfig.config[:audience]

    true
  end

  def valid_signature?
    jwk = find_jwk

    raise InvalidSignatureKeyException, 'Could not match token\'s kid with jwks from issuer' if jwk.nil?

    # verify_iss duplicates what valid_issuer?, left here for future references
    # removing valid_issuer? requires a full rewrite of tests because of order of operations
    verification_options = {
      algorithm: 'RS512',
      verify_expiration: true,  # Verify token expiration (exp claim)
      verify_not_before: true,  # Verify not before (nbf claim)
      aud: TokenValidator::ValidatorConfig.config[:audience],
      verify_aud: true,
      iss: TokenValidator::ValidatorConfig.config[:issuer_url], # Verify issuer (iss claim)
      verify_iss: true  # Verify audience (aud claim)
    }

    verified = JWT.decode(@access_token, jwk.to_key, true, verification_options)[0]

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

  def find_jwk
    jwk = search_jwks
    if jwk.nil?
      TokenValidator::OauthTokenService.instance.clear
      jwk = search_jwks
    end
    jwk
  end

  def search_jwks
    jwks = TokenValidator::OauthTokenService.instance.signing_key
    return nil if jwks.blank?

    jwks.each do |key|
      return key if key['kid'] == decoded_jwt['kid']
    end

    nil
  end
end
