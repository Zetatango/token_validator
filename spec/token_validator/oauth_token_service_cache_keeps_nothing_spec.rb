# frozen_string_literal: true

require 'spec_helper'

# An additional issuer's machine tokens and signing keys when the cache keeps nothing -- a store that
# discards everything or refuses every write, as Redis does while it is unreachable. The process holds
# its own copy of the last good token and key set, under the same rules as the cache would apply, so
# each call is not another request to the issuer. Having no cache at all is a different case and is
# covered where that is tested: every call fetches.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  def orders_api = AdditionalIssuerContext::ORDERS_API
  def billing_api = AdditionalIssuerContext::BILLING_API
  def token_url = AdditionalIssuerContext::EXTRA_TOKEN_URL
  def jwks_url = AdditionalIssuerContext::EXTRA_JWKS_URL
  def start = Time.at(1_800_000_000)
  def just = AdditionalIssuerContext::MILLISECOND

  def at(seconds_after_start, &)
    Timecop.freeze(start + seconds_after_start, &)
  end

  stores_that_keep_nothing = {
    'discards everything' => -> { ActiveSupport::Cache::NullStore.new },
    'refuses every write' => -> { AdditionalIssuerContext::WriteRefusingStore.new }
  }

  stores_that_keep_nothing.each do |kind, store|
    describe "a cache that #{kind}" do
      before do
        use_cache(store.call)
        Timecop.freeze(start)
      end

      describe 'a machine token' do
        before { stub_token_endpoint_echoing_audience(expires_in: 3600) }

        it 'is requested once, then reused for every call, whichever way it is asked for' do
          tokens = Array.new(5) { token_for(orders_api) }
          entry_tokens = Array.new(5) { service.access_token(AdditionalIssuerContext::EXTRA_ISSUER) }
          headers = Array.new(5) { service.oauth_auth_header(AdditionalIssuerContext::EXTRA_ISSUER, audience: orders_api) }

          expect(tokens.map { |token| token[:token] }).to all(eq("token-for-#{orders_api}"))
          expect(entry_tokens.map { |token| token[:token] }).to all(eq("token-for-#{AdditionalIssuerContext::ENTRY_API}"))
          expect(headers).to all(eq(authorization: "Bearer token-for-#{orders_api}"))
          expect(token_requests(orders_api)).to have_been_made.once
          expect(token_requests(AdditionalIssuerContext::ENTRY_API)).to have_been_made.once
        end

        it 'is held until three minutes before it expires, and not a moment longer' do
          token_for(orders_api)

          at(3420 - just) { token_for(orders_api) }
          expect(token_requests(orders_api)).to have_been_made.once

          at(3420 + just) { token_for(orders_api) }
          expect(token_requests(orders_api)).to have_been_made.twice
        end

        it 'is never handed to a caller asking for another audience' do
          token_for(orders_api)

          expect(token_for(billing_api)).to include(token: "token-for-#{billing_api}")
          expect(token_requests(billing_api)).to have_been_made.once
        end

        it 'is never handed to a caller asking another issuer' do
          other = 'https://other-tenant.ca.auth0.com/'
          TokenValidator::ValidatorConfig.additional_issuers = [extra_entry, extra_entry.merge(issuer_url: other, jwks_url: "#{other}jwks.json")]
          stub_request(:post, "#{other}oauth/token").to_return(status: 200, body: token_body('other-token', 3600))
          token_for(orders_api)

          expect(service.access_token(other, audience: orders_api)).to include(token: 'other-token')
        end

        it 'is not served once it has expired, when the issuer cannot be reached for another' do
          token_for(orders_api)
          stub_request(:post, token_url).to_return(status: 503)

          at(3600 + 1) { expect(token_for(orders_api)).to be_nil }
        end

        it 'is forgotten by clear' do
          token_for(orders_api)

          service.clear
          token_for(orders_api)

          expect(token_requests(orders_api)).to have_been_made.twice
        end

        it 'is requested once for callers who ask at the same moment, who all get that token' do
          stub_request(:post, token_url).to_return do
            sleep 0.05
            { status: 200, body: token_body('shared', 3600) }
          end
          gate = Queue.new
          threads = Array.new(20) { Thread.new { gate.pop && token_for(orders_api) } }
          20.times { gate << true }

          expect(values_of(threads).map { |token| token[:token] }).to all(eq('shared'))
          expect(token_requests(orders_api)).to have_been_made.once
        end

        it 'is not held when the issuer failed, so the next call after the backoff asks again' do
          stub_request(:post, token_url).to_return({ status: 503 }, { status: 200, body: token_body('recovered', 3600) })
          expect(token_for(orders_api)).to be_nil

          at(10 + just) { expect(token_for(orders_api)).to include(token: 'recovered') }
        end
      end

      describe 'a signing key set' do
        before { stub_request(:get, jwks_url).to_return(key_set_response('a'), key_set_response('b')) }

        it 'is fetched once, then reused for every call' do
          expect(Array.new(5) { kids_of(extra_keys) }).to all(eq(['a']))
          expect(key_requests).to have_been_made.once
        end

        it 'is fetched again once it is an hour old, and not a moment before' do
          extra_keys

          at(1.hour - just) { expect(kids_of(extra_keys)).to eq(['a']) }
          expect(key_requests).to have_been_made.once

          at(1.hour + just) { expect(kids_of(extra_keys)).to eq(['b']) }
          expect(key_requests).to have_been_made.twice
        end

        it 'is kept when its refresh fails, for a day from when it was fetched and not a moment longer' do
          stub_request(:get, jwks_url).to_return(key_set_response('a'), { status: 503 })
          extra_keys

          at(1.hour + 1.minute) { expect(kids_of(extra_keys)).to eq(['a']) }
          at(24.hours - just) { expect(kids_of(extra_keys)).to eq(['a']) }
          at(24.hours + just) { expect(extra_keys).to be_nil }
        end

        it 'is never handed out for another issuer' do
          other = 'https://other-tenant.ca.auth0.com/'
          TokenValidator::ValidatorConfig.additional_issuers = [extra_entry, extra_entry.merge(issuer_url: other, jwks_url: "#{other}jwks.json")]
          stub_request(:get, "#{other}jwks.json").to_return(key_set_response('other'))
          extra_keys

          expect(kids_of(service.signing_key(other))).to eq(['other'])
        end

        it 'is forgotten by clear' do
          extra_keys

          service.clear

          expect(kids_of(extra_keys)).to eq(['b'])
        end

        it 'is fetched once for callers who ask at the same moment, who all get that set' do
          stub_request(:get, jwks_url).to_return do
            sleep 0.05
            key_set_response('shared')
          end
          gate = Queue.new
          threads = Array.new(20) { Thread.new { gate.pop && extra_keys } }
          20.times { gate << true }

          expect(values_of(threads).map { |keys| kids_of(keys) }).to all(eq(['shared']))
          expect(key_requests).to have_been_made.once
        end

        it 'is not held when the issuer failed, so the next call after the backoff asks again' do
          stub_request(:get, jwks_url).to_return({ status: 503 }, key_set_response('recovered'))
          expect(extra_keys).to be_nil

          at(10 + just) { expect(kids_of(extra_keys)).to eq(['recovered']) }
        end
      end
    end
  end

  # The process's own copy is consulted whenever the shared cache has no entry, not only when the
  # cache is unable to keep anything: flushing, evicting or clearing the shared cache does not make
  # this process fetch again at once. A token lasts until three minutes before it expires and a key
  # set until it is an hour old; TokenService.clear in a process forgets that process's copies.
  describe 'a cache that works, once what it held has been removed' do
    before do
      use_cache
      Timecop.freeze(start)
    end

    describe 'a machine token' do
      before do
        stub_token_endpoint_echoing_audience(expires_in: 3600)
        token_for(orders_api)
        cache.clear
      end

      it 'is still reused with no request, until three minutes before it expires, and not a moment longer' do
        at(1) { expect(token_for(orders_api)).to include(token: "token-for-#{orders_api}") }
        at(3420 - just) { token_for(orders_api) }
        expect(token_requests(orders_api)).to have_been_made.once

        at(3420 + just) { token_for(orders_api) }
        expect(token_requests(orders_api)).to have_been_made.twice
      end

      it 'is not reused once TokenService.clear has been called in the process' do
        TokenValidator::TokenService.clear

        token_for(orders_api)

        expect(token_requests(orders_api)).to have_been_made.twice
      end

      it 'gives way to the shared cache whenever that holds a token' do
        other = { token: 'fetched-by-another-process', expires: start.to_i + 3600, expires_in: 3600 }
        cache.write(service.send(:access_token_cache_key, AdditionalIssuerContext::EXTRA_ISSUER, orders_api), other,
                    namespace: service.send(:namespace), expires_in: 3000)

        expect(token_for(orders_api)).to include(token: 'fetched-by-another-process')
        expect(token_requests(orders_api)).to have_been_made.once
      end
    end

    describe 'a signing key set' do
      before do
        stub_request(:get, jwks_url).to_return(key_set_response('a'), key_set_response('b'))
        extra_keys
        cache.clear
      end

      it 'is still reused with no request, until it is an hour old, and not a moment longer' do
        at(1) { expect(kids_of(extra_keys)).to eq(['a']) }
        at(1.hour - just) { expect(kids_of(extra_keys)).to eq(['a']) }
        expect(key_requests).to have_been_made.once

        at(1.hour + just) { expect(kids_of(extra_keys)).to eq(['b']) }
        expect(key_requests).to have_been_made.twice
      end

      it 'is not reused once TokenService.clear has been called in the process' do
        TokenValidator::TokenService.clear

        expect(kids_of(extra_keys)).to eq(['b'])
        expect(key_requests).to have_been_made.twice
      end

      it 'gives way to the shared cache whenever that holds a set' do
        cache.write(service.send(:jwks_cache_key, AdditionalIssuerContext::EXTRA_ISSUER), JSON::JWK::Set.new([jwk('fetched-by-another-process')]),
                    namespace: service.send(:namespace), expires_in: 1.day)

        expect(kids_of(extra_keys)).to eq(['fetched-by-another-process'])
        expect(key_requests).to have_been_made.once
      end
    end
  end
end
