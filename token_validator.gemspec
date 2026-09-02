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

  spec.required_ruby_version = '>= 3.3.0'

  # This gem is never pushed to a gem host. Releases are annotated git tags on this repository,
  # and each consumer pins one in its Gemfile (decision D23, 2026-09-02):
  #
  #   gem 'token_validator', github: 'Zetatango/token_validator', tag: 'v0.7.0'
  #
  # The value below is deliberately not a URL so that `gem push` fails on purpose.
  spec.metadata['allowed_push_host'] = 'none: released by git tag, never pushed (D23)'

  spec.files = Dir['{app,config,lib}/**/*', 'Rakefile', 'README.md']

  spec.add_dependency 'json-jwt'
  spec.add_dependency 'jwt'
  spec.add_dependency 'rack'
  spec.add_dependency 'rails', '>= 7.0.0'
  spec.add_dependency 'rest-client'
  spec.add_dependency 'webmock'

  spec.add_development_dependency 'bundler-audit'
  spec.add_development_dependency 'codacy-coverage'
  spec.add_development_dependency 'codecov'
  spec.add_development_dependency 'json-jwt'
  spec.add_development_dependency 'jwt'
  spec.add_development_dependency 'rack'
  spec.add_development_dependency 'rest-client'
  spec.add_development_dependency 'rspec-collection_matchers'
  spec.add_development_dependency 'rspec_junit_formatter'
  spec.add_development_dependency 'rspec-mocks'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'rubocop-performance'
  spec.add_development_dependency 'rubocop-rspec'
  spec.add_development_dependency 'rubocop_runner'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'timecop'
  spec.add_development_dependency 'webmock'
end
