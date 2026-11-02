# frozen_string_literal: true

require 'spec_helper'

# An additional issuer's machine tokens and signing keys when the cache cannot do its part: it refuses
# writes, discards everything, is absent, or is asked to hold a token that is already within the
# three minutes held back. The caller still gets an answer, and never one that has expired.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  let(:orders_api) { AdditionalIssuerContext::ORDERS_API }
  let(:token_url) { AdditionalIssuerContext::EXTRA_TOKEN_URL }
  let(:jwks_url) { AdditionalIssuerContext::EXTRA_JWKS_URL }

  describe 'a cache that refuses every write' do
    before { use_cache(AdditionalIssuerContext::WriteRefusingStore.new) }

    it 'still hands out the token it fetched, fetching again on the next call' do
      stub_token_endpoint_echoing_audience

      tokens = Array.new(3) { token_for(orders_api) }

      expect(tokens.map { |token| token[:token] }).to all(eq("token-for-#{orders_api}"))
      expect(token_requests(orders_api)).to have_been_made.times(3)
    end

    it 'still answers nil, without raising, when the token cannot be fetched' do
      stub_request(:post, token_url).to_return(status: 503)

      expect(Array.new(3) { token_for(orders_api) }).to all(be_nil)
    end

    it 'still answers the keys it fetched, fetching again on the next call' do
      stub_request(:get, jwks_url).to_return(key_set_response('a'))

      expect(Array.new(3) { kids_of(extra_keys) }).to all(eq(['a']))
      expect(key_requests).to have_been_made.times(3)
    end
  end

  describe 'a cache that discards everything' do
    before { use_cache(ActiveSupport::Cache::NullStore.new) }

    it 'answers tokens and keys, and never raises' do
      stub_token_endpoint_echoing_audience
      stub_request(:get, jwks_url).to_return(key_set_response('a'))

      expect(token_for(orders_api)).to include(token: "token-for-#{orders_api}")
      expect(service.access_token(AdditionalIssuerContext::EXTRA_ISSUER)).to include(token: "token-for-#{AdditionalIssuerContext::ENTRY_API}")
      expect(kids_of(extra_keys)).to eq(['a'])
      expect(kids_of(refetched_extra_keys)).to eq(['a'])
    end

    it 'answers nil and no keys, without raising, when the endpoints fail' do
      stub_request(:post, token_url).to_return(status: 503)
      stub_request(:get, jwks_url).to_return(status: 503)

      expect(token_for(orders_api)).to be_nil
      expect(extra_keys).to be_nil
      expect(refetched_extra_keys).to be_nil
    end
  end

  describe 'a cache that discards everything, asked about an unknown key id again and again' do
    before do
      use_cache(ActiveSupport::Cache::NullStore.new)
      stub_request(:get, jwks_url).to_return(key_set_response('a'))
    end

    it 'still fetches the keys at most once a minute' do
      5.times { refetched_extra_keys }

      expect(key_requests).to have_been_made.once
    end

    it 'fetches again once the minute has passed, and not a moment before' do
      Timecop.freeze(Time.at(1_800_000_000))
      refetched_extra_keys

      Timecop.freeze(Time.at(1_800_000_000 + 60 - AdditionalIssuerContext::MILLISECOND)) { refetched_extra_keys }
      expect(key_requests).to have_been_made.once

      Timecop.freeze(Time.at(1_800_000_000 + 60 + AdditionalIssuerContext::MILLISECOND)) { refetched_extra_keys }
      expect(key_requests).to have_been_made.twice
    end

    it 'counts the minute for each issuer separately' do
      other = 'https://other-tenant.ca.auth0.com/'
      TokenValidator::ValidatorConfig.additional_issuers = [extra_entry, extra_entry.merge(issuer_url: other, jwks_url: "#{other}jwks.json")]
      stub_request(:get, "#{other}jwks.json").to_return(key_set_response('b'))
      refetched_extra_keys

      expect(kids_of(service.refetch_signing_key(other))).to eq(['b'])
    end
  end

  describe 'no cache at all' do
    before { allow(Rails).to receive(:cache).and_return(nil) }

    it 'answers tokens and keys for every audience and issuer, fetching on every call' do
      stub_token_endpoint_echoing_audience
      stub_request(:get, jwks_url).to_return(key_set_response('a'))

      2.times do
        expect(token_for(orders_api)).to include(token: "token-for-#{orders_api}")
        expect(kids_of(extra_keys)).to eq(['a'])
        expect(kids_of(refetched_extra_keys)).to eq(['a'])
      end

      expect(token_requests(orders_api)).to have_been_made.twice
      expect(key_requests).to have_been_made.times(4)
    end

    it 'answers nil, without raising, when the endpoints fail' do
      stub_request(:post, token_url).to_return(status: 503)
      stub_request(:get, jwks_url).to_return(status: 503)

      expect(token_for(orders_api)).to be_nil
      expect(extra_keys).to be_nil
      expect(refetched_extra_keys).to be_nil
    end
  end

  # A token that lives no longer than the three minutes held back can never be reused, so a response
  # offering one is unusable: nothing is handed out and no token is cached, the response is logged, and
  # the issuer is not asked again for the usual 10 seconds, as after any other failed fetch.
  describe 'a token response whose lifetime is no more than the three minutes held back' do
    around do |example|
      original = ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time
      example.run
    ensure
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = original
    end

    before do
      use_cache
      Timecop.freeze(Time.at(1_800_000_000))
    end

    unusable_lifetimes = [0, -5, 100, 179, 179.5, 180]

    [true, false].each do |strict_cache|
      unusable_lifetimes.each do |lifetime|
        it "answers nil and an empty header, caches no token and never raises for #{lifetime} s, strict cache expiry #{strict_cache}" do
          ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = strict_cache
          stub_request(:post, token_url).to_return(status: 200, body: token_body('short-lived', lifetime))

          written = keys_written_to_cache do
            expect(token_for(orders_api)).to be_nil
            expect(service.oauth_auth_header(AdditionalIssuerContext::EXTRA_ISSUER, audience: orders_api)).to eq({})
          end

          expect(written).to all(start_with('failed-fetch-'))
        end
      end
    end

    it 'logs one line for the response, naming the issuer and never the token' do
      stub_request(:post, token_url).to_return(status: 200, body: token_body('short-lived-secret', 100))

      token_for(orders_api)

      expect(log_lines.string.lines.size).to eq(1)
      expect(log_lines.string).to include(AdditionalIssuerContext::EXTRA_ISSUER).and(satisfy { |text| !text.include?('short-lived-secret') })
    end

    it 'is not asked for again until 10 seconds have passed, as after any failed fetch' do
      stub_request(:post, token_url).to_return(status: 200, body: token_body('short-lived', 100))
      token_for(orders_api)

      Timecop.freeze(Time.at(1_800_000_000 + 10 - AdditionalIssuerContext::MILLISECOND)) { expect(token_for(orders_api)).to be_nil }
      expect(token_requests(orders_api)).to have_been_made.once

      Timecop.freeze(Time.at(1_800_000_000 + 10 + AdditionalIssuerContext::MILLISECOND)) { expect(token_for(orders_api)).to be_nil }
      expect(token_requests(orders_api)).to have_been_made.twice
    end

    it 'is never served later, however long afterwards: it is asked for again and refused again' do
      stub_request(:post, token_url).to_return(status: 200, body: token_body('short-lived', 100))
      token_for(orders_api)

      Timecop.freeze(Time.at(1_800_000_000 + (3 * 86_400))) { expect(token_for(orders_api)).to be_nil }

      expect(token_requests(orders_api)).to have_been_made.twice
    end

    it 'is replaced by a usable token as soon as the issuer offers one after the backoff' do
      stub_request(:post, token_url).to_return({ status: 200, body: token_body('short-lived', 100) }, { status: 200, body: token_body('usable') })
      token_for(orders_api)

      Timecop.freeze(Time.at(1_800_000_000 + 11)) { expect(token_for(orders_api)).to include(token: 'usable') }
    end

    it 'does not hold back the same issuer\'s tokens for other audiences' do
      stub_request(:post, token_url).with(body: hash_including('audience' => orders_api)).to_return(status: 200, body: token_body('short', 100))
      stub_request(:post, token_url).with(body: hash_including('audience' => AdditionalIssuerContext::BILLING_API))
                                    .to_return(status: 200, body: token_body('long'))
      token_for(orders_api)

      expect(token_for(AdditionalIssuerContext::BILLING_API)).to include(token: 'long')
    end
  end

  # A lifetime that is not a finite number cannot be turned into an expiry time, so such a response is
  # as unusable as one that lives too briefly: nothing is handed out, no token is cached, the response
  # is logged, and the issuer is not asked again for 10 seconds.
  describe 'a token response whose lifetime is not a finite number' do
    let(:started_at) { Time.at(1_800_000_000) }

    before { Timecop.freeze(started_at) }

    non_finite_lifetimes = ['1e999', '-1e999']

    {
      'a memory cache' => -> { ActiveSupport::Cache::MemoryStore.new },
      'a cache that turns an expiry into whole milliseconds' => -> { AdditionalIssuerContext::MillisecondExpiryStore.new }
    }.each do |kind, store|
      non_finite_lifetimes.each do |lifetime|
        it "answers nil and an empty header, caches no token and never raises for #{lifetime} s, in #{kind}" do
          use_cache(store.call)
          stub_request(:post, token_url).to_return(status: 200, body: %({"access_token":"t","expires_in":#{lifetime}}))

          written = keys_written_to_cache do
            expect(token_for(orders_api)).to be_nil
            expect(service.oauth_auth_header(AdditionalIssuerContext::EXTRA_ISSUER, audience: orders_api)).to eq({})
          end

          expect(written).to all(start_with('failed-fetch-'))
        end
      end
    end

    it 'logs one line for the response, naming the issuer and never the token' do
      use_cache
      stub_request(:post, token_url).to_return(status: 200, body: '{"access_token":"infinite-secret","expires_in":1e999}')

      token_for(orders_api)

      expect(log_lines.string.lines.size).to eq(1)
      expect(log_lines.string).to include(AdditionalIssuerContext::EXTRA_ISSUER).and(satisfy { |text| !text.include?('infinite-secret') })
    end

    it 'is not asked for again until 10 seconds have passed, and is never served from the cache' do
      use_cache(AdditionalIssuerContext::MillisecondExpiryStore.new)
      stub_request(:post, token_url).to_return(status: 200, body: '{"access_token":"t","expires_in":1e999}')
      token_for(orders_api)

      Timecop.freeze(started_at + 10 - AdditionalIssuerContext::MILLISECOND) { expect(token_for(orders_api)).to be_nil }
      expect(token_requests(orders_api)).to have_been_made.once

      Timecop.freeze(started_at + 10 + AdditionalIssuerContext::MILLISECOND) { expect(token_for(orders_api)).to be_nil }
      expect(token_requests(orders_api)).to have_been_made.twice
    end
  end

  describe 'a token response whose lifetime is just over the three minutes held back' do
    before do
      use_cache
      Timecop.freeze(Time.at(1_800_000_000))
      stub_request(:post, token_url).to_return(status: 200, body: token_body('over', 181))
    end

    it 'is handed out and held for the second that remains' do
      2.times { expect(token_for(orders_api)).to include(token: 'over') }

      expect(token_requests(orders_api)).to have_been_made.once
    end

    it 'is asked for again once that second has passed' do
      token_for(orders_api)

      Timecop.freeze(Time.at(1_800_000_000 + 1 + AdditionalIssuerContext::MILLISECOND)) { token_for(orders_api) }

      expect(token_requests(orders_api)).to have_been_made.twice
    end
  end
end
