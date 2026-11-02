# Changelog

Releases are annotated git tags on this repository — this gem is never pushed to a gem host.
Consumers pin a tag in their Gemfile (decision D23):

```ruby
gem 'token_validator', github: 'Zetatango/token_validator', tag: 'v0.7.0'
```

## v0.9.0 — 2026-11-01

One machine token per receiving API, and safer fetching of an additional issuer's signing keys and
machine tokens. **The primary issuer is unchanged, failures included**, and a caller that names no
audience sends, caches and receives exactly what it did. `bin/parity_check` against v0.8.0 is
identical across all 30 scenarios: the existing 28, plus 2 new ones for an additional issuer's
machine token asked for without an audience.

A consumer that trusts only the primary issuer sees no change at all. One that also trusts an
additional issuer sees the changes below on that issuer's path only.

### Added

- `audience:` on `OauthTokenService#access_token` and `#oauth_auth_header`. (LEN-1710)

  A service that calls several others needs a machine token for each, because each accepts only
  tokens naming its own API. An additional issuer can now be asked for a token for a named API.

  Contract, pinned by spec:

  - **omitted, nothing changes**: the request names the entry's `audience`, and the cache key, the
    three-minute early expiry and the nil on failure are those of v0.8.0
  - a non-blank String asks for that audience, and the token is cached under the issuer **and** the
    audience, apart from every other audience's token
  - **anything else answers nil and requests nothing**: an explicit `nil`, a blank or non-String
    value, any audience for the primary issuer (which is never sent one), and any audience for an
    issuer configured only for verification. Only leaving the keyword out means "the entry's
    audience", so a setting that was never configured cannot quietly fetch a token for another API

- `OauthTokenService#refetch_signing_key(issuer = nil)`, which fetches an issuer's keys again for a
  token naming a key id the cached set lacks, and answers the set to search. `TokenService` now uses
  it in place of `clear_signing_key`. For the primary issuer it does exactly what that retry always
  did. For an additional issuer it is limited and keeps the cached keys when it fails (below), which
  makes it the safer call for a consumer verifying tokens itself. `clear_signing_key` is unchanged.

### Changed — additional issuers only

- **Timeouts.** Key and token fetches allow 5 s to connect and 10 s to read, instead of the HTTP
  client's default of about a minute each.
- **Backoff.** After a failed fetch, that issuer's keys, or that issuer and audience's machine token,
  are not asked for again for 10 s. Calls in the meantime answer as the failure did. Shared through
  the cache, so it holds every process back.
- **Unknown key ids.** A token naming a key id the cached set lacks makes this library fetch that
  issuer's keys again at most once a minute, across every process sharing the cache. The fetched set
  replaces the cached one **only when the fetch succeeded**. Before, every such token dropped the
  cached keys and fetched them again, so anyone could turn each request into a key fetch, and one
  such request during an outage at the issuer cost every valid caller its keys.
- **Key expiry.** A cached set is fetched again once it is an hour old, so a key the issuer has
  withdrawn stops being trusted. When that fetch fails the cached set stays in use, so a brief outage
  refuses nobody, for up to a day. The set is still a `JSON::JWK::Set` under the same cache key, so
  processes running an earlier release that share the cache during a rolling deploy can still read
  it.
- **One fetch at a time.** Within one process, callers that miss the cache together wait for one
  fetch of that token, or of that issuer's keys, instead of each making their own. A different
  audience or issuer is never held up. While a stale key set is being refreshed, other callers keep
  using it rather than wait.

  The backoff, the refetch limit, the expiry and the single fetch all need a cache. With
  `Rails.cache` unset, every call fetches, as before.

### Fixed — additional issuers only

- **Every failed fetch is a clean answer**: no machine token (nil, an empty header), or a refused
  token for verification. It is never an exception. Each of these escaped before, or produced a bad
  token:
  - DNS failures, connection resets, unreachable hosts, TLS errors and broken streams, which the
    HTTP client does not wrap in its own exceptions;
  - a key set that is not JSON, is a JSON value other than an object, has no list of keys, or holds
    no key that can verify a signature;
  - a published key that cannot be turned into a verification key. It is left out of the set, so a
    token naming it is refused like any unknown key, instead of raising during verification;
  - a token response that is not a JSON object, lacks a non-empty `access_token`, or lacks a
    numeric `expires_in`. A missing `access_token` used to be cached and handed out as an empty
    bearer header until it expired.

  Each failure is logged once, naming the issuer, the audience and the error class or what was wrong
  with the response. Nothing from the response body is ever logged, because a body can echo a
  credential.

### Not changed

- **The primary issuer's fetching**, deliberately: the HTTP client's default timeouts, the exceptions
  it has always let through, no backoff, no limit on refetching keys, and no expiry on cached keys.
  Pinned by spec. A later release may extend the same handling to it.
- **`OauthTokenService#get_token_info`**, which asks only the primary issuer about a token. It keeps
  that issuer's behaviour above, and a later release may extend the same handling to it too.

### Tooling

- `bin/parity_check` also compares an additional issuer's machine token asked for without an
  audience: the request it sends and the token and header it answers.

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
