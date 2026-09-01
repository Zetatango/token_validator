[![CircleCI](https://circleci.com/gh/Zetatango/token_validator.svg?style=svg&circle-token=37e4e43c64911cdbf98df7d86ad584e4df0fa8b7)](https://circleci.com/gh/Zetatango/token_validator) [![codecov](https://codecov.io/gh/Zetatango/token_validator/branch/master/graph/badge.svg)](https://codecov.io/gh/Zetatango/token_validator) [![Depfu](https://badges.depfu.com/badges/7ba12605815fa6dccbabc3f522a33a40/overview.svg)](https://depfu.com/github/Zetatango/token_validator?project_id=6684)

# TokenValidator
This gem is used to validate OAuth2 authentication tokens returned from a provided issuer (for example, the Ario Identity Provider). This allows other components/services to verify that the user who presents the token is authenticated and authorized to access the requested resource.

## Usage

### Initialization
Something like the following should be included in an initializer in your Rails project:
```ruby
TokenValidator::ValidatorConfig.configure(
  client_id: ENV['client_id'],
  client_secret: ENV['client_secret'],
  requested_scope: ENV['scope'],
  issuer_url: ENV['issuer_url'],
  audience: ENV['audience']
)
```

### Trusting more than one issuer

The validator can trust several issuers at once. Each entry describes one issuer completely, and a
token is verified against the entry whose `issuer_url` matches its `iss` claim -- that entry's
signing keys, algorithm and audience, not the primary issuer's:

```ruby
TokenValidator::ValidatorConfig.configure(
  # ... the settings above, which describe the primary issuer ...
  additional_issuers: [
    {
      issuer_url: ENV['auth0_issuer_url'],       # required
      jwks_url: ENV['auth0_jwks_url'],           # required
      audience: ENV['auth0_audience'],           # required
      algorithm: 'RS256',                        # required
      client_id: ENV['auth0_client_id'],         # optional: only to obtain machine tokens
      client_secret: ENV['auth0_client_secret'], # optional: only to obtain machine tokens
      token_url: ENV['auth0_token_url']          # optional: defaults to <issuer_url>/oauth/token
    }
  ]
)
```

- **Matching is exact, and a trailing slash is part of the address.** One provider reachable at two
  addresses needs an entry for each -- which is the usual case for a partner-branded vanity URL,
  since the canonical issuer URL ends in a slash and the vanity one generally does not. The two
  entries can name the same `jwks_url`.
- `algorithm` must be asymmetric (`RS*`, `ES*` or `PS*`); a shared-secret algorithm is refused when
  it is configured, not when a token arrives.
- An entry that omits `client_id` and `client_secret` is trusted to *verify* tokens but is never
  asked for one, rather than falling back to the primary issuer's credentials.
- A malformed entry raises `TokenValidator::ValidatorConfig::InvalidIssuerConfigException`. Rescue
  it in your initializer, report it, and re-raise, so the application refuses to boot on an issuer
  configuration it cannot trust. The exception names the offending position and key but never the
  value, because these entries hold a client secret.
- Omitting `additional_issuers` leaves behaviour exactly as it was: one issuer, verified the way it
  always has been.

## Installation
Add this line to your application's Gemfile:

```ruby
gem 'token_validator'
```

And then execute:
```bash
$ bundle
```

Or install it yourself as:
```bash
$ gem install token_validator
```

## Development
Development on this project should occur on separate feature branches and pull requests should be submitted. When submitting a pull request, the pull request comment template should be filled out as much as possible to ensure a quick review and increase the likelihood of the pull request being accepted.

### Ruby

This application requires:

*   Ruby version: 2.7.1

Ruby 2.7.1 and greater requires OpenSSL 1.1+. To link to Homebrew's upgraded version of OpenSSL, add the following to your bash profile

```shell script
export RUBY_CONFIGURE_OPTS="--with-openssl-dir=$(brew --prefix openssl@1.1)"
```

If you do not have Ruby installed, it is recommended you use ruby-install and chruby to manage Ruby versions.

```bash
brew install ruby-install chruby
ruby-install ruby 2.7.1
```

Add the following lines to ~/.bash_profile:

```bash
source /usr/local/opt/chruby/share/chruby/chruby.sh
source /usr/local/opt/chruby/share/chruby/auto.sh
```

Set Ruby version to 2.7.1:

```bash
source ~/.bash_profile
chruby 2.7.1
```

### Running Tests
```ruby
rspec # Without code coverage
COVERAGE=true rspec # with code coverage
```

## Contributing
Bug reports and pull requests are welcome on GitHub at https://github.com/Zetatango/token_validator
