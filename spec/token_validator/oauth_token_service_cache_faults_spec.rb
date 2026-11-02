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

  describe 'a machine token whose lifetime is shorter than the three minutes held back' do
    let(:short_lived) { { status: 200, body: token_body('short-lived', 100) } }

    around do |example|
      original = ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time
      example.run
    ensure
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = original
    end

    before do
      use_cache
      stub_request(:post, token_url).to_return(short_lived)
    end

    it 'does not raise when the cache refuses a negative expiry' do
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = true

      expect { token_for(orders_api) }.not_to raise_error
    end

    it 'is not handed out again once its lifetime has passed, when the cache ignores a negative expiry' do
      ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = false
      token_for(orders_api)

      Timecop.travel(Time.now + 101.seconds) { token_for(orders_api) }

      expect(token_requests(orders_api)).to have_been_made.twice
    end
  end

  describe 'a machine token whose lifetime is exactly the three minutes held back, or just over' do
    before do
      use_cache
      Timecop.freeze(Time.at(1_800_000_000))
      stub_request(:post, token_url).with(body: hash_including('audience' => orders_api)).to_return(status: 200, body: token_body('exact', 180))
      stub_request(:post, token_url).with(body: hash_including('audience' => AdditionalIssuerContext::BILLING_API))
                                    .to_return(status: 200, body: token_body('over', 181))
    end

    it 'is handed out, but not held, at exactly three minutes' do
      2.times { expect(token_for(orders_api)).to include(token: 'exact') }

      expect(token_requests(orders_api)).to have_been_made.twice
    end

    it 'is handed out and held, for a second, at one second over' do
      2.times { expect(token_for(AdditionalIssuerContext::BILLING_API)).to include(token: 'over') }

      expect(token_requests(AdditionalIssuerContext::BILLING_API)).to have_been_made.once
    end
  end
end
