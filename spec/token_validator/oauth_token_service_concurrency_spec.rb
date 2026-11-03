# frozen_string_literal: true

require 'spec_helper'

# Many callers in one process meeting an additional issuer's token or key endpoint at once: one fetch
# is made for them, nobody waits when a usable answer is already held, and a fetch that is abandoned or
# fails never leaves the others waiting behind it.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'
  include_context 'with signed tokens'

  let(:arrived) { Queue.new }
  let(:release) { Queue.new }

  def callers = 25
  def orders_api = AdditionalIssuerContext::ORDERS_API
  def token_url = AdditionalIssuerContext::EXTRA_TOKEN_URL
  def jwks_url = AdditionalIssuerContext::EXTRA_JWKS_URL

  before { use_cache }

  # Frees any request still held, so no thread outlives its example.
  after { callers.times { release << :go } }

  # Holds every request to +url+ until the example releases it, announcing each arrival.
  def hold_endpoint(method, url, response)
    stub_request(method, url).to_return do
      arrived << :arrived
      release.pop
      response
    end
  end

  def wait_for_arrival(timeout: 5)
    arrived.pop(timeout:) || raise("no request reached the endpoint within #{timeout}s")
  end

  # Starts +count+ threads that all begin together, running the block.
  def start_together(count)
    gate = Queue.new
    threads = Array.new(count) { |index| Thread.new { gate.pop && yield(index) } }
    count.times { gate << true }
    threads
  end

  def ignoring_errors
    yield
  rescue StandardError
    nil
  end

  # Caches a token for +audience+, then holds the endpoint so the next fetch stays in flight.
  def cache_token_then_hold_endpoint(audience)
    stub_request(:post, token_url).with(body: hash_including('audience' => audience)).to_return(status: 200, body: token_body('cached'))
    token_for(audience)
    hold_endpoint(:post, token_url, { status: 200, body: token_body('held') })
  end

  # Caches keys, lets them go stale, then holds the endpoint and starts the one caller that refreshes them.
  def start_stale_refresh
    stub_request(:get, jwks_url).to_return(key_set_response('a'))
    extra_keys
    Timecop.travel(Time.now + 61.minutes)
    hold_endpoint(:get, jwks_url, key_set_response('b'))
    Thread.new { extra_keys }.tap { wait_for_arrival }
  end

  def finished?(threads, within: 3)
    threads.all? { |thread| thread.join(within) }
  end

  describe 'a machine token' do
    it 'is fetched once for every caller that asks for it at the same moment' do
      hold_endpoint(:post, token_url, { status: 200, body: token_body('shared') })
      threads = start_together(callers) { token_for(orders_api) }
      wait_for_arrival
      callers.times { release << :go }

      expect(values_of(threads).map { |token| token&.fetch(:token) }).to all(eq('shared'))
      expect(token_requests(orders_api)).to have_been_made.once
    end

    it 'is asked for once, and nil is the answer to every waiting caller, when the fetch fails' do
      hold_endpoint(:post, token_url, { status: 503 })
      threads = start_together(callers) { token_for(orders_api) }
      wait_for_arrival
      callers.times { release << :go }

      expect(values_of(threads)).to all(be_nil)
      expect(token_requests(orders_api)).to have_been_made.once
    end

    it 'is not asked for at all by callers arriving during the backoff' do
      stub_request(:post, token_url).to_return(status: 503)
      token_for(orders_api)

      threads = start_together(callers) { token_for(orders_api) }

      expect(values_of(threads)).to all(be_nil)
      expect(token_requests(orders_api)).to have_been_made.once
    end

    it 'leaves callers served from the cache unaffected by a fetch for another audience that is stuck' do
      cache_token_then_hold_endpoint(AdditionalIssuerContext::BILLING_API)
      stuck = Thread.new { token_for(orders_api) }
      wait_for_arrival

      threads = start_together(callers) { token_for(AdditionalIssuerContext::BILLING_API) }

      expect(finished?(threads)).to be(true)
      expect(values_of(threads).map { |token| token[:token] }).to all(eq('cached'))
      release << :go
      values_of(stuck)
    end

    it 'does not leave the others waiting when the caller doing the fetch is stopped partway' do
      hold_endpoint(:post, token_url, { status: 200, body: token_body })
      doomed = Thread.new { token_for(orders_api) }
      wait_for_arrival
      doomed.kill
      doomed.join

      stub_request(:post, token_url).to_return(status: 200, body: token_body('after'))
      waiting = Thread.new { token_for(orders_api) }

      expect(finished?([waiting])).to be(true)
      expect(waiting.value).to include(token: 'after')
    end

    it 'does not leave the others waiting when storing the token raises, whatever the first caller then sees' do
      stub_request(:post, token_url).to_return(status: 200, body: token_body('stored'))
      allow(cache).to receive(:write).and_raise(Errno::ENOSPC)
      ignoring_errors { token_for(orders_api) }
      allow(cache).to receive(:write).and_call_original

      waiting = Thread.new { token_for(orders_api) }

      expect(finished?([waiting])).to be(true)
      expect(waiting.value).to include(token: 'stored')
    end
  end

  describe 'signing keys' do
    it 'are fetched once for every caller that finds none cached' do
      hold_endpoint(:get, jwks_url, key_set_response('a'))
      threads = start_together(callers) { extra_keys }
      wait_for_arrival
      callers.times { release << :go }

      expect(values_of(threads).map { |keys| kids_of(keys) }).to all(eq(['a']))
      expect(key_requests).to have_been_made.once
    end

    it 'are refreshed once when stale, while every other caller carries on at once with the set it holds' do
      refresher = start_stale_refresh

      others = start_together(callers - 1) { extra_keys }

      expect(finished?(others, within: 2)).to be(true)
      expect(values_of(others).map { |keys| kids_of(keys) }).to all(eq(['a']))
      expect(refresher).to be_alive
      release << :go
      expect(kids_of(values_of(refresher).first)).to eq(['b'])
      expect(key_requests).to have_been_made.twice
    end

    it 'are fetched again only once, however many tokens naming an unknown key id arrive together' do
      stub_request(:get, jwks_url).to_return(key_set_response('a'))
      extra_keys

      threads = start_together(callers) { refetched_extra_keys }

      expect(values_of(threads).map { |keys| kids_of(keys) }).to all(eq(['a']))
      expect(key_requests).to have_been_made.twice
    end

    it 'are fetched at most once more than the first time for a flood of tokens naming unknown key ids' do
      TokenValidator::ValidatorConfig.additional_issuers = [extra_entry.merge(audience: 'https://primary.example.com', algorithm: 'RS512')]
      stub_request(:get, jwks_url).to_return(key_set_response('a'))
      unknown_kid_token = JWT.encode(
        { sub: 's', iat: Time.now.to_i, exp: 30.minutes.from_now.to_i, iss: AdditionalIssuerContext::EXTRA_ISSUER,
          aud: 'https://primary.example.com', scopes: ['test:api'], kid: 'no-such-kid' }, primary_signing_key, 'RS512'
      )

      threads = start_together(callers) { validates?(unknown_kid_token) }

      expect(values_of(threads)).to all(be(false))
      expect(WebMock::RequestRegistry.instance.times_executed(WebMock::RequestPattern.new(:get, jwks_url))).to be <= 2
    end

    it 'cannot be refetched in the middle of a refresh without both finishing' do
      refresher = start_stale_refresh

      refetcher = Thread.new { refetched_extra_keys }
      sleep 0.1
      release << :go
      release << :go

      expect(finished?([refresher, refetcher], within: 5)).to be(true)
    end

    it 'do not leave the others waiting when the caller doing the fetch is stopped partway' do
      hold_endpoint(:get, jwks_url, key_set_response('a'))
      doomed = Thread.new { extra_keys }
      wait_for_arrival
      doomed.kill
      doomed.join

      stub_request(:get, jwks_url).to_return(key_set_response('a'))
      waiting = Thread.new { extra_keys }

      expect(finished?([waiting])).to be(true)
      expect(kids_of(waiting.value)).to eq(['a'])
    end
  end
end
