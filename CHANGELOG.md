# Changelog

Releases are annotated git tags on this repository — this gem is never pushed to a gem host.
Consumers pin a tag in their Gemfile (decision D23):

```ruby
gem 'token_validator', github: 'Zetatango/token_validator', tag: 'v0.7.0'
```

## v0.8.0 — 2026-09-23

Adds one shape for a token's custom claims, whichever issuer emitted them, and a per-issuer
`claim_namespace` to describe where that issuer puts them. **Additive**: no existing behaviour
changes, and an issuer entry that omits the new key is byte-identical to one written before it
existed, so no caller of v0.7.x is affected by upgrading.

### Added

- `TokenValidator::ClaimNormalizer`, and `TokenService#normalized_claims` / `#namespaced_claims?`
  on top of it. (LEN-1225)

  The sibling of `granted_scopes`, for the same reason one release earlier. Where `granted_scopes`
  answers what a token *permits*, this answers who and what it *describes* — and issuers disagree
  about the claim **names** for all of it. One issuer emits custom claims unprefixed at the top
  level; another requires every custom claim to sit under a namespace. A consumer reading a claim
  directly gets a value from one issuer and `nil` from the other, and `nil` is indistinguishable
  from "this token said nothing" — so the branch goes dark with no error and no log line. That is
  the failure `granted_scopes` was made public to prevent for the permission claims; this is the
  same failure for everything else.

  Contract, pinned by spec because consumers depend on it:

  - **the issuer is decided by `iss`**, via the same `issuer_config_for` lookup whose key and
    algorithm the signature was verified against. The resolution happens once, so the namespace
    used to read the claims and the key used to verify them cannot disagree. This is why it belongs
    in this library rather than in each consumer
  - **every key in `CLAIMS` is always present**, and a claim the token did not carry is `nil`.
    Omitting absent claims would make `key?` a question about the issuer rather than about the token
  - **a namespaced issuer is read only under its namespace**, with no fallback to the flat name. A
    fallback would read a claim the issuer never asserted — anything at the top level of such a
    token got there another way
  - **`user_guid` prefers its claim and falls back to `sub`.** An issuer that has no such claim puts
    the guid in the subject; one that does may have a subject of its own. Preferring the claim means
    the contract decides, and the subject is never parsed
  - `false` is preserved as `false`. A recorded opt-out is not an absence

  Call it once `valid_access_token?` has answered true. Like `granted_scopes` it reads claims, so an
  unreadable token raises rather than answering `nil`.

- `claim_namespace`, a new **optional** per-issuer key in `additional_issuers`. (LEN-1225)

  The literal prefix an issuer puts in front of each custom claim, concatenated with the claim name
  and nothing else — whatever separator it ends in belongs in the configured value. Omit the key for
  an issuer that emits unprefixed claims.

  It is configuration rather than a constant in this library deliberately. A namespace together with
  the claim names under it is a particular estate's token schema, and this repository is public;
  values of that kind belong in the private consumer that owns them.

  Supplying it blank, or as anything other than a String, **raises at configuration time**. A prefix
  that matches nothing makes every namespaced claim read `nil` while the token still verifies, which
  is the silent total failure this key exists to make impossible — boot is the only place it is
  cheap to catch. An omitted key and an empty String are different mistakes and get different
  answers. The exception names the offending value, which is the second and only other exception to
  the rule that these messages name index and key alone: a claim namespace is not a secret, it
  prefixes claims inside every token the issuer signs, and an operator cannot fix a typo they cannot
  see.

## v0.7.1 — 2026-09-11

Exposes the permission union that v0.7.0 introduced. **Purely additive**: one method moves from
private to public, no behaviour changes, and no caller of v0.7.0 is affected by upgrading.

### Added

- `TokenValidator::TokenService#granted_scopes` is now **public**. It answers everything a token
  grants, unioned across whichever of `scopes`, `scope` and `permissions` the token carries, or
  `nil` when it carries none of them. (LEN-1159)

  The union already decided whether a request was *allowed*; consumers separately need to know
  *what* it was allowed, in order to build their own per-request context. zetatango read the raw
  `scopes` claim to do that — the only shape the primary issuer emits — so under an Auth0 token its
  context was empty and every scope-dependent branch went dark **silently**: no error, no log line,
  a 200 response, and a scope check that never matched. Exposing the union is what stops each
  consumer reimplementing it, differently.

  Contract, now pinned by spec because consumers depend on it:

  - a space-separated `scope` string is **split**, never returned whole — `include?` on a String
    matches a substring, so a caller asking `granted_scopes.include?('ztt:api')` of `"ztt:apikey"`
    would otherwise be told yes
  - `nil` means the token carried no permission claim; `[]` means it carried one and it was empty.
    The two are different answers and callers branch on the difference
  - it reads claims, so an unreadable token **raises** rather than answering `nil` — `JWT::DecodeError`
    for a token that does not decode, `JwtFormatException` for a payload that decodes to something
    other than an object. "Could not be read" must never be mistaken for "carried nothing"

  Call it once `valid_access_token?` has answered true.

## v0.7.0 — 2026-09-02

The multi-issuer release: the validator can trust several token issuers at once, selected per token
by its `iss` claim. With `additional_issuers` unconfigured, the release is **backward compatible
rather than byte-identical** — proven behaviourally against v0.6.3 by `bin/parity_check`
(token_validator#518, extended in #522) across a **28-scenario matrix: 14 scenarios are
byte-identical and 14 differ deliberately** (every one listed under Added/Changed/Fixed below), all
in one direction. Nothing v0.6.3 accepted is rejected, nothing raises that did not raise before, no
scenario makes more HTTP requests, and the machine-token client half is byte-identical. Five of the
differences are v0.6.3 crashes that are now clean rejections — see the last two Fixed entries.

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
- A token segment that is valid base64url of valid JSON but **not an object** (`null`, a list, a
  number, a string, `true`) is rejected as `JwtFormatException` instead of letting `NoMethodError`
  or `TypeError` escape `valid_access_token?`, whose contract is to answer true or false. The header
  case crashed inside the `jwt` gem itself, so the guard wraps the decode call. (#520, LEN-1078)
- Issuer entry values are stored as **frozen copies**, so a validated `algorithm` or `issuer_url`
  cannot be mutated after the fact through `additional_issuers` — which would have bypassed the
  algorithm allowlist or made an unconfigured address resolve. Entries built from `ENV` arrive
  mutable, so freezing the entry Hash alone was not enough. Freezing a copy leaves the caller's own
  strings untouched. (#522)

### Tooling

- `bin/parity_check` aborts when `--lib` does not exist, instead of silently measuring whatever
  library is already loaded and diffing clean against itself. (#521)

## v0.6.3 — baseline (retrospective)

The last single-issuer version, never tagged at the time. Every consumer's lockfile referenced it by
commit SHA. `v0.6.3` is tagged retrospectively at `c8ba842` — the revision all four applications
were locked to when multi-issuer work began, and the baseline `bin/parity_check` compares against.
