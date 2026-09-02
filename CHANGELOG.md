# Changelog

Releases are annotated git tags on this repository — this gem is never pushed to a gem host.
Consumers pin a tag in their Gemfile (decision D23):

```ruby
gem 'token_validator', github: 'Zetatango/token_validator', tag: 'v0.7.0'
```

## v0.7.0 — 2026-09-02

The multi-issuer release: the validator can trust several token issuers at once, selected per token
by its `iss` claim. With `additional_issuers` unconfigured, behaviour is unchanged — proven
behaviourally against v0.6.3 by `bin/parity_check` (token_validator#518): across a 23-scenario
matrix, nothing v0.6.3 accepted is rejected, nothing raises that did not raise before, no scenario
makes more HTTP requests, and the machine-token client half is byte-identical.

### Added

- `additional_issuers` configuration: each entry carries `issuer_url`, `jwks_url`, `audience` and
  `algorithm`, plus optional `client_id`/`client_secret`/`token_url` for issuers machine tokens are
  obtained from. Matching on `iss` is exact — a trailing slash is part of the address. (#510, LEN-960)
- Per-issuer signing-key fetch and cache isolation: one issuer's keys can never verify another's
  token, and clearing clears every issuer. (#513, LEN-1074)
- Signature verification against whichever trusted issuer signed the token: algorithm, audience and
  issuer are taken from the matched entry. A token's `kid` is read from the JOSE header first
  (Auth0's placement), falling back to the payload (roadrunner's). (#515, LEN-1076)
- Machine-token acquisition from additional issuers, cached per issuer; Auth0's `audience` parameter
  included. An issuer configured without credentials yields no token rather than falling back to the
  primary issuer's. The primary issuer's request is byte-identical to v0.6.3. (#514, LEN-1075)
- Permissions are read from all three claim shapes — the `scopes` list, the space-separated `scope`
  string, and the `permissions` list — and unioned. A scope matches whole, never as a substring. (#517, LEN-961)
- `bin/parity_check`: behavioural comparison of two checkouts of this gem, used as the release gate. (#518, LEN-1078)

### Changed

- An issuer configured with an algorithm outside the asymmetric allowlist (`RS*`/`ES*`/`PS*`, exact
  RFC 7518 spelling) is refused at configuration time with
  `ValidatorConfig::InvalidIssuerConfigException`, failing the boot. (#512, LEN-1069)
- A token signed with an algorithm other than its issuer's configured one now raises
  `InvalidAlgorithmException` ("Invalid algorithm: …") instead of `JwtFormatException`
  ("Invalid token"), so alerting can tell a wrong algorithm from garbage. The claimed algorithm is
  echoed into the message only when it is one of the permitted constants. (#516, LEN-1077)
- The retry after an unrecognised `kid` evicts only that issuer's cached JWKS instead of clearing
  the whole cache namespace — an unauthenticated token can no longer flush every issuer's keys and
  machine tokens. `TokenService.clear` still clears everything. (#516)

### Fixed

- A validly-signed token missing `iat` or `exp`, or carrying either as a non-number, is rejected
  with `MissingAccessTokenField` instead of letting `ArgumentError`/`NoMethodError` escape
  `valid_access_token?`. `nbf` is type-checked when present. (#516, LEN-1077)
- Fractional `NumericDate` values (permitted by RFC 7519) no longer read a just-issued token as
  issued in the future: the clock comparison is float against float. (#516)

## v0.6.3 — baseline (retrospective)

The last single-issuer version, never tagged at the time. Every consumer's lockfile referenced it by
commit SHA. `v0.6.3` is tagged retrospectively at `c8ba842` — the revision all four applications
were locked to when multi-issuer work began, and the baseline `bin/parity_check` compares against.
