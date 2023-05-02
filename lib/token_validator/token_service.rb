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
    @decoded_jwt ||= JSON::JWT.decode @access_token, :skip_verification
  end

  def valid_access_token?

    valid_structure? && !expired?
  rescue JSON::JWT::InvalidFormat => e
    TokenValidator::ValidatorConfig.logger.error "Invalid JWT format: #{e.message}"
    false
  rescue TokenServiceException => e
    TokenValidator::ValidatorConfig.logger.error "Invalid access token: #{e.message}"
    false
  end

  def refresh!(refresh_token, params = {}); end

  private

  def valid_structure?
    valid_issuer? && valid_signature? && valid_audience? && valid_contents? && valid_scope?
  end

  def valid_scope?
    token_scope = scope(decoded_jwt)
    raise InvalidScope, 'Missing scopes' unless token_scope.present?
    return true if @expected_scopes.blank?

    valid = false
    @expected_scopes.each do |scope|
      valid ||= token_scope.include? scope
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
    puts "decoded_jwt['aud']=#{decoded_jwt['aud']}"
    puts "TokenValidator::ValidatorConfig.config[:audience]=#{TokenValidator::ValidatorConfig.config[:audience]}"
    raise InvalidAudienceException, 'Invalid audience' unless decoded_jwt['aud'].include? TokenValidator::ValidatorConfig.config[:audience]

    true
  end

  def valid_signature?
    jwk = find_jwk

    raise InvalidSignatureKeyException, 'Could not match token\'s kid with jwks from issuer' if jwk.nil?

    verified = JOSE::JWT.verify_strict(jwk, %w[RS256 RS512], @access_token)[0]

    raise InvalidSignatureException, 'Invalid signature' unless verified

    true
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
      return key if key['kid'] == kid(decoded_jwt)
    end

    nil
  end

  def kid(decoded_jwt)
    return decoded_jwt['kid'] if decoded_jwt.key?('kid')

    decoded_jwt.header['kid']
  end

  def scope(decoded_jwt)
    return decoded_jwt['scopes'] if decoded_jwt.key?('scopes')

    decoded_jwt['scope']
  end

  def valid_url?(url)
    uri = URI.parse(url)
    (uri.is_a?(URI::HTTPS) || (uri.is_a?(URI::HTTP) && !Rails.env.production?)) && uri.host.present?
  end

  def valid_issuer?
    raise InvalidIssuerException, 'No issuer present' unless decoded_jwt.key?('iss')

    issuer = decoded_jwt['iss']

    raise InvalidIssuerException, 'Issuer must be a valid url' unless valid_url? issuer
    raise InvalidIssuerException, 'Invalid issuer' unless issuer == TokenValidator::ValidatorConfig.config[:issuer_url]

    true
  end
end
