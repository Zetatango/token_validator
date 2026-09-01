# frozen_string_literal: true

class TokenValidator::ValidatorConfig
  # Raised when +additional_issuers+ is given a value this library cannot trust.
  #
  # Consumers rescue this in their own initializer, report it, and re-raise so the
  # application refuses to boot on a bad issuer configuration (decision D21).
  #
  # The message names the offending position and key only. It must never name the
  # value: these entries sit beside +client_secret+ in this class, and every consumer
  # forwards this exception to an error tracker.
  class InvalidIssuerConfigException < RuntimeError; end

  # Every trusted issuer entry must carry all of these, non-blank.
  REQUIRED_ISSUER_KEYS = %i[issuer_url jwks_url audience algorithm].freeze

  # The algorithm the primary issuer has always signed with.
  PRIMARY_ISSUER_ALGORITHM = 'RS512'

  # The only algorithms an issuer entry may name. Asymmetric signatures exclusively:
  # every issuer this library will ever trust publishes a public key and signs with the
  # private half, so a shared-secret (+HS*+) algorithm is never correct here. It is also
  # the dangerous one -- under +HS*+ the verification key *is* the signing key, so the
  # JWKS material we fetch in public would become enough to mint tokens.
  #
  # This list is what makes the jwt gem's empty-key HMAC bypass unreachable once M1-03
  # stops hard-coding PRIMARY_ISSUER_ALGORITHM and starts honouring this value.
  #
  # Spelling is exact, and deliberately so: the jwt gem matches +alg+ case-insensitively
  # (+JWA.find+ downcases, +valid_alg?+ uses +casecmp+), which means 'hs256' is every bit
  # as dangerous as 'HS256'. Comparing the value as given rejects both. Do not add an
  # +upcase+ ahead of this check -- accepting 'rs256' would store a value that no longer
  # equals the RFC 7518 name anything downstream compares against.
  PERMITTED_ISSUER_ALGORITHMS = %w[
    RS256 RS384 RS512
    ES256 ES384 ES512
    PS256 PS384 PS512
  ].freeze

  @config = {
    issuer_url: '',
    client_id: '',
    client_secret: '',
    requested_scope: '',
    audience: ''
  }

  @allowed_config_keys = %i[audience client_id client_secret issuer_url requested_scope]

  # Held outside @config deliberately. An existing spec asserts that hash equals exactly
  # the five keys above, and this gem reaches its consumers before any of them switches
  # issuer, so the shape of @config must not change at all.
  @additional_issuers = [].freeze

  def self.configure(options = {})
    options = options.transform_keys(&:to_sym)

    options.each { |key, value| @config[key] = value if @allowed_config_keys.include?(key) }

    # nil means "not configured" rather than "configured wrongly", so a consumer whose
    # feature flag is off can pass the key through unset without failing to boot.
    self.additional_issuers = options[:additional_issuers] unless options[:additional_issuers].nil?
  end

  def self.additional_issuers=(issuers)
    @additional_issuers = validated_issuers(issuers).freeze
  end

  class << self
    attr_reader :config
  end

  # Defaulted here rather than relying solely on the assignment in the class body, so the
  # list can never be nil however this class is loaded or reloaded. A nil here would make
  # the lookup raise for any consumer that upgrades the gem without configuring anything --
  # which is every consumer, on the release before they switch issuer.
  def self.additional_issuers
    @additional_issuers ||= [].freeze
  end

  # The settings for +issuer+, or nil when this library does not trust it.
  #
  # Answers for the primary issuer as well as the configured additional ones, so no
  # caller ever has to ask "is this the original provider?" (decision D20). Matching is
  # exact: the answer decides which key verifies a token, so a near-miss must not match.
  def self.issuer_config_for(issuer)
    return nil if issuer.blank?
    return primary_issuer_config if issuer == @config[:issuer_url]

    additional_issuers.find { |entry| entry[:issuer_url] == issuer }
  end

  def self.primary_issuer_config
    {
      issuer_url: @config[:issuer_url],
      # Built the way TokenCacheHelper#oauth_path builds it, so the primary issuer keeps
      # resolving to exactly the address it resolves to today.
      jwks_url: "#{@config[:issuer_url]}/oauth/discovery/keys",
      audience: @config[:audience],
      algorithm: PRIMARY_ISSUER_ALGORITHM
    }.freeze
  end
  private_class_method :primary_issuer_config

  def self.validated_issuers(issuers)
    raise InvalidIssuerConfigException, "additional_issuers must be an Array, got #{issuers.class}" unless issuers.is_a?(Array)

    issuers.each_with_index.map { |entry, index| validated_issuer_entry(entry, index) }
  end
  private_class_method :validated_issuers

  def self.validated_issuer_entry(entry, index)
    raise InvalidIssuerConfigException, "additional_issuers[#{index}] must be a Hash, got #{entry.class}" unless entry.is_a?(Hash)

    # Read only the supported keys, in either symbol or string form. Anything else is dropped
    # rather than carried along, which is what `configure` does with keys it does not recognise
    # -- and this never calls `to_sym` on a key that may not respond to it.
    supported = REQUIRED_ISSUER_KEYS.to_h { |key| [key, entry.key?(key) ? entry[key] : entry[key.to_s]] }

    REQUIRED_ISSUER_KEYS.each do |key|
      raise InvalidIssuerConfigException, "additional_issuers[#{index}] is missing a value for #{key}" if supported[key].blank?
    end

    # Named in the message because an algorithm is not a secret and the operator cannot
    # fix a typo they cannot see. Nothing else from the entry joins it -- see D21.
    unless PERMITTED_ISSUER_ALGORITHMS.include?(supported[:algorithm])
      raise InvalidIssuerConfigException,
            "additional_issuers[#{index}] names algorithm #{supported[:algorithm].inspect}, " \
            "which is not one of #{PERMITTED_ISSUER_ALGORITHMS.join(', ')}"
    end

    supported.freeze
  end
  private_class_method :validated_issuer_entry

  def self.logger
    @logger ||= Rails.logger.nil? ? Logger.new($stdout) : Rails.logger
    @logger
  end

  class << self
    attr_writer :logger
  end
end
