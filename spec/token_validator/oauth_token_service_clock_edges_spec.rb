# frozen_string_literal: true

require 'spec_helper'

# The time limits on an additional issuer's machine tokens and signing keys, probed a millisecond
# either side of each boundary: a token is handed out until three minutes before it expires, a failed
# fetch is not repeated for 10 seconds, keys are fetched again after an hour and after an unknown key
# id at most once a minute, and keys the issuer cannot be asked for again are trusted for at most a day.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  let(:orders_api) { AdditionalIssuerContext::ORDERS_API }
  let(:start) { Time.at(1_800_000_000) }
  let(:just) { 0.001 }

  before do
    use_cache
    Timecop.freeze(start)
  end

  def at(seconds_after_start, &)
    Timecop.freeze(start + seconds_after_start, &)
  end

  describe 'a machine token with a one hour lifetime' do
    before { stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return(status: 200, body: token_body('t', 3600)) }

    [['asked for by audience', ->(service, issuer, audience) { service.access_token(issuer, audience:) }],
     ['asked for without one', ->(service, issuer, _audience) { service.access_token(issuer) }]].each do |how, ask|
      it "is served from the cache until three minutes before it expires, #{how}" do
        issuer = AdditionalIssuerContext::EXTRA_ISSUER
        ask.call(service, issuer, orders_api)

        at(3420 - just) { ask.call(service, issuer, orders_api) }
        expect(token_requests).to have_been_made.once

        at(3420 + just) { ask.call(service, issuer, orders_api) }
        expect(token_requests).to have_been_made.twice
      end
    end
  end

  describe 'after a failed machine token fetch' do
    before do
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return({ status: 503 }, { status: 200, body: token_body })
      token_for(orders_api)
    end

    it 'does not ask again until 10 seconds have passed, then does' do
      at(10 - just) { expect(token_for(orders_api)).to be_nil }
      expect(token_requests).to have_been_made.once

      at(10 + just) { expect(token_for(orders_api)).to include(token: 'extra-token') }
      expect(token_requests).to have_been_made.twice
    end

    it 'starts a new 10 seconds when the fetch after the first backoff fails again' do
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return(status: 503)

      at(11) { token_for(orders_api) }
      at(11 + 10 - just) { token_for(orders_api) }
      expect(token_requests).to have_been_made.twice

      at(11 + 10 + just) { token_for(orders_api) }
      expect(token_requests).to have_been_made.times(3)
    end
  end

  describe 'a cached signing key set' do
    before { stub_request(:get, AdditionalIssuerContext::EXTRA_JWKS_URL).to_return(key_set_response('a'), key_set_response('b')) }

    it 'is fetched again once it is an hour old, and not a moment before' do
      extra_keys

      at(1.hour - just) { expect(kids_of(extra_keys)).to eq(['a']) }
      expect(key_requests).to have_been_made.once

      at(1.hour + just) { expect(kids_of(extra_keys)).to eq(['b']) }
      expect(key_requests).to have_been_made.twice
    end
  end

  describe 'a cached signing key set whose refreshes keep failing' do
    before do
      stub_request(:get, AdditionalIssuerContext::EXTRA_JWKS_URL).to_return(key_set_response('a'), { status: 503 })
      extra_keys
    end

    it 'is trusted until it is a day old and not after' do
      at(1.hour + 1) { extra_keys }
      at(24.hours - 20) { extra_keys }

      at(24.hours - just) { expect(kids_of(extra_keys)).to eq(['a']) }
      at(24.hours + just) { expect(extra_keys).to be_nil }
    end

    it 'keeps being served through the backoff between attempts to refresh it' do
      at(1.hour + 1) { expect(kids_of(extra_keys)).to eq(['a']) }
      at(1.hour + 6) { expect(kids_of(extra_keys)).to eq(['a']) }
      expect(key_requests).to have_been_made.twice
    end
  end

  describe 'a cached signing key set that was last refreshed successfully' do
    it 'counts its day from that refresh, not from the first fetch' do
      stub_request(:get, AdditionalIssuerContext::EXTRA_JWKS_URL)
        .to_return(key_set_response('a'), key_set_response('b'), { status: 503 })
      extra_keys
      at(23.hours) { expect(kids_of(extra_keys)).to eq(['b']) }

      at(47.hours - 20) { extra_keys }
      at(47.hours - just) { expect(kids_of(extra_keys)).to eq(['b']) }
      at(47.hours + just) { expect(extra_keys).to be_nil }
    end
  end

  describe 'refetching for an unknown key id' do
    before do
      stub_request(:get, AdditionalIssuerContext::EXTRA_JWKS_URL).to_return(key_set_response('a'))
      extra_keys
      refetched_extra_keys
    end

    it 'fetches again only once a minute has passed since the last refetch' do
      at(60 - just) { refetched_extra_keys }
      expect(key_requests).to have_been_made.twice

      at(60 + just) { refetched_extra_keys }
      expect(key_requests).to have_been_made.times(3)
    end

    it 'counts the minute from the last refetch, however many were refused in between' do
      at(30) { 5.times { refetched_extra_keys } }

      at(60 + just) { refetched_extra_keys }

      expect(key_requests).to have_been_made.times(3)
    end
  end

  describe 'after a failed signing key fetch' do
    it 'does not ask again until 10 seconds have passed, then does' do
      stub_request(:get, AdditionalIssuerContext::EXTRA_JWKS_URL).to_return({ status: 503 }, key_set_response('a'))
      extra_keys

      at(10 - just) { expect(extra_keys).to be_nil }
      expect(key_requests).to have_been_made.once

      at(10 + just) { expect(kids_of(extra_keys)).to eq(['a']) }
      expect(key_requests).to have_been_made.twice
    end
  end
end
