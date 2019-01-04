# frozen_string_literal: true

$LOAD_PATH.push File.expand_path('lib', __dir__)

# Maintain your gem's version:
require 'token_validator/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |spec|
  spec.name        = 'token_validator'
  spec.version     = TokenValidator::VERSION
  spec.authors     = ['Greg Fletcher']
  spec.email       = ['greg.fletcher@arioplatform.com']
  spec.homepage    = 'https://github.com/Zetatango/token_validator'
  spec.summary     = 'A library for validating OAuth2 tokens.'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise 'RubyGems 2.0 or newer is required to protect against ' \
      'public gem pushes.'
  end

  spec.files = Dir['{app,config,lib}/**/*', 'Rakefile', 'README.md']

  spec.add_dependency 'jose'
  spec.add_dependency 'json-jwt'
  spec.add_dependency 'jwt'
  spec.add_dependency 'rack'
  spec.add_dependency 'rails'
  spec.add_dependency 'rest-client'
  spec.add_dependency 'webmock'

  spec.add_development_dependency 'bundler-audit'
  spec.add_development_dependency 'codecov'
  spec.add_development_dependency 'jose'
  spec.add_development_dependency 'json-jwt'
  spec.add_development_dependency 'jwt'
  spec.add_development_dependency 'rack'
  spec.add_development_dependency 'rest-client'
  spec.add_development_dependency 'rspec-collection_matchers'
  spec.add_development_dependency 'rspec-mocks'
  spec.add_development_dependency 'rspec_junit_formatter'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'rubocop-rspec'
  spec.add_development_dependency 'rubocop_runner'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'timecop'
  spec.add_development_dependency 'webmock'
end
