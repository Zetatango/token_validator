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
    attr_reader :config, :additional_issuers
  end

  # The settings for +issuer+, or nil when this library does not trust it.
  #
  # Answers for the primary issuer as well as the configured additional ones, so no
  # caller ever has to ask "is this the original provider?" (decision D20). Matching is
  # exact: the answer decides which key verifies a token, so a near-miss must not match.
  def self.issuer_config_for(issuer)
    return nil if issuer.blank?
    return primary_issuer_config if issuer == @config[:issuer_url]

    @additional_issuers.find { |entry| entry[:issuer_url] == issuer }
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

    entry = entry.transform_keys(&:to_sym)

    REQUIRED_ISSUER_KEYS.each do |key|
      raise InvalidIssuerConfigException, "additional_issuers[#{index}] is missing a value for #{key}" if entry[key].blank?
    end

    entry.freeze
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
