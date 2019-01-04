# frozen_string_literal: true

class TokenValidator::ValidatorConfig
  @config = {
    issuer_url: '',
    client_id: '',
    client_secret: '',
    requested_scope: '',
    audience: ''
  }

  @allowed_config_keys = %i[audience client_id client_secret issuer_url requested_scope]

  def self.configure(options = {})
    options.each { |key, value| @config[key.to_sym] = value if @allowed_config_keys.include? key.to_sym }
  end

  class << self
    attr_reader :config
  end

  def self.logger
    @logger ||= Rails.logger.nil? ? Logger.new(STDOUT) : Rails.logger
    @logger
  end

  class << self
    attr_writer :logger
  end
end
