# frozen_string_literal: true

require 'spec_helper'

# How often an additional issuer's signing keys can be fetched again on a caller's request, and what
# a caller can do to the keys already held. Both ways of asking for fresh keys -- refetch_signing_key
# and clear_signing_key -- share one limit of one fetch a minute per issuer, fetch before they
# replace anything, and never leave the issuer without the keys it had.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  def jwks_url = AdditionalIssuerContext::EXTRA_JWKS_URL
  def issuer = AdditionalIssuerContext::EXTRA_ISSUER
  def start = Time.at(1_800_000_000)
  def just = AdditionalIssuerContext::MILLISECOND

  def at(seconds_after_start, &)
    Timecop.freeze(start + seconds_after_start, &)
  end

  def cleared_keys
    service.clear_signing_key(issuer)
  end

  before do
    use_cache
    Timecop.freeze(start)
  end

  describe 'clearing an additional issuer\'s signing keys' do
    before { stub_request(:get, jwks_url).to_return(key_set_response('a'), key_set_response('b'), key_set_response('c')) }

    it 'fetches the keys again and replaces the held set with what it fetched' do
      extra_keys

      cleared_keys

      expect(kids_of(extra_keys)).to eq(['b'])
      expect(key_requests).to have_been_made.twice
    end

    it 'fetches nothing within a minute of an earlier refetch, and leaves the held keys in place' do
      extra_keys
      refetched_extra_keys

      at(1) { cleared_keys }

      expect(kids_of(extra_keys)).to eq(['b'])
      expect(key_requests).to have_been_made.twice
    end

    it 'takes the minute for itself, so a refetch right after it fetches nothing' do
      extra_keys
      cleared_keys

      at(1) { refetched_extra_keys }

      expect(key_requests).to have_been_made.twice
    end

    it 'fetches nothing for repeated calls within the minute, and again once it has passed, and not a moment before' do
      extra_keys
      cleared_keys
      5.times { |second| at(1 + second) { cleared_keys } }
      expect(key_requests).to have_been_made.twice

      at(60 - just) { cleared_keys }
      expect(key_requests).to have_been_made.twice

      at(60 + just) { cleared_keys }
      expect(key_requests).to have_been_made.times(3)
    end

    it 'keeps the held keys, and answers them, when the fetch fails' do
      stub_request(:get, jwks_url).to_return(key_set_response('a'), { status: 503 })
      extra_keys

      cleared_keys

      expect(kids_of(extra_keys)).to eq(['a'])
    end

    it 'keeps the held keys when the fetch returns something unusable' do
      stub_request(:get, jwks_url).to_return(key_set_response('a'), { status: 200, body: '{"keys":[]}' })
      extra_keys

      cleared_keys

      expect(kids_of(extra_keys)).to eq(['a'])
    end

    it 'never removes the held keys from the cache, whatever the fetch does' do
      extra_keys
      key = service.send(:jwks_cache_key, issuer)
      stub_request(:get, jwks_url).to_raise(Timeout::Error)

      cleared_keys

      expect(cache.read(key, namespace: service.send(:namespace))).to be_present
    end

    # A refresh of keys gone stale failed, so the issuer is not asked again for 10 seconds.
    describe 'during the backoff after a failed fetch' do
      before do
        stub_request(:get, jwks_url).to_return(key_set_response('a'), { status: 503 }, key_set_response('b'))
        extra_keys
        Timecop.freeze(start + 1.hour + 1.minute)
        extra_keys
      end

      it 'fetches nothing and keeps the held keys' do
        Timecop.freeze(start + 1.hour + 1.minute + 5) { cleared_keys }

        expect(kids_of(extra_keys)).to eq(['a'])
        expect(key_requests).to have_been_made.twice
      end

      it 'does not use up the minute, so the first call once the backoff has passed fetches' do
        Timecop.freeze(start + 1.hour + 1.minute + 5) { cleared_keys }

        Timecop.freeze(start + 1.hour + 1.minute + 10 + just) { cleared_keys }

        expect(kids_of(extra_keys)).to eq(['b'])
      end
    end

    it 'fetches nothing, and keeps the held keys, when another process fetched within the minute' do
      extra_keys
      cache.write(service.send(:jwks_refetch_key, extra_entry), true, namespace: service.send(:namespace), expires_in: 60.seconds)

      at(1) { cleared_keys }

      expect(kids_of(extra_keys)).to eq(['a'])
      expect(key_requests).to have_been_made.once
    end

    it 'answers a clean nothing, without raising, when there are no keys held and the fetch fails' do
      stub_request(:get, jwks_url).to_return(status: 503)

      expect { cleared_keys }.not_to raise_error
      expect(extra_keys).to be_nil
    end

    it 'leaves another issuer\'s keys and every machine token alone' do
      other = 'https://other-tenant.ca.auth0.com/'
      TokenValidator::ValidatorConfig.additional_issuers = [extra_entry, extra_entry.merge(issuer_url: other, jwks_url: "#{other}jwks.json")]
      stub_request(:get, "#{other}jwks.json").to_return(key_set_response('other'))
      stub_token_endpoint_echoing_audience
      [service.signing_key(other), token_for(AdditionalIssuerContext::ORDERS_API), extra_keys]

      cleared_keys
      service.signing_key(other)
      token_for(AdditionalIssuerContext::ORDERS_API)

      expect(a_request(:get, "#{other}jwks.json")).to have_been_made.once
      expect(token_requests(AdditionalIssuerContext::ORDERS_API)).to have_been_made.once
    end

    it 'does nothing, and raises nothing, for an issuer this library does not trust' do
      expect { service.clear_signing_key('https://unknown.example.com/') }.not_to raise_error
      expect(requests_made).to eq(0)
    end
  end

  describe 'clearing an additional issuer\'s signing keys when the cache keeps nothing' do
    before do
      use_cache(ActiveSupport::Cache::NullStore.new)
      stub_request(:get, jwks_url).to_return(key_set_response('a'), { status: 503 })
    end

    it 'keeps the last good set when the fetch fails' do
      extra_keys

      cleared_keys

      expect(kids_of(extra_keys)).to eq(['a'])
    end
  end

  describe 'the minute a process waits before fetching an issuer\'s keys again' do
    before { stub_request(:get, jwks_url).to_return(key_set_response('a'), key_set_response('b')) }

    # Another process holds the shared minute: this one is turned away without fetching, and must not
    # count that minute against itself once it has gone.
    it 'is not used up by a request that another process\'s fetch turned away' do
      extra_keys
      cache.write(service.send(:jwks_refetch_key, extra_entry), true, namespace: service.send(:namespace), expires_in: 60.seconds)

      at(30) { refetched_extra_keys }
      expect(key_requests).to have_been_made.once

      at(60 + just) { expect(kids_of(refetched_extra_keys)).to eq(['b']) }
      expect(key_requests).to have_been_made.twice
    end

    it 'is still held by a request that won the shared minute' do
      extra_keys
      refetched_extra_keys

      at(59) { refetched_extra_keys }

      expect(key_requests).to have_been_made.twice
    end
  end

  # A request that is cut short -- a request timeout, an interrupt -- can arrive in a thread at any
  # moment, including the instant it takes the lock that lets one thread refresh stale keys. The lock
  # must never be left held, or no thread in the process would ever refresh that issuer's keys again.
  describe 'an interrupt that arrives as the lock for refreshing stale keys is taken' do
    # Delivers +error+ into the calling thread from another thread, once +lock+ has been taken, and
    # waits until it is pending, so it reaches the thread exactly as the lock is recorded as taken.
    def interrupt_after_taking(lock, error)
      caller_thread = Thread.current
      allow(lock).to receive(:try_lock).and_wrap_original do |try_lock|
        taken = try_lock.call
        Thread.new { caller_thread.raise(error) }.join
        sleep 0.01
        taken
      end
    end

    before do
      stub_request(:get, jwks_url).to_return(key_set_response('a'), key_set_response('b'))
      extra_keys
      Timecop.freeze(start + 1.hour + 1.minute)
    end

    it 'does not leave the lock held, so the next caller refreshes the keys' do
      lock = service.send(:flight_lock, service.send(:jwks_cache_key, issuer))
      interrupt_after_taking(lock, AdditionalIssuerContext::RequestCutShort)

      expect { extra_keys }.to raise_error(AdditionalIssuerContext::RequestCutShort)
      expect(lock).not_to be_locked

      allow(lock).to receive(:try_lock).and_call_original
      expect(kids_of(extra_keys)).to eq(['b'])
    end
  end
end
