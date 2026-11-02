# frozen_string_literal: true

require 'spec_helper'

# An additional issuer's keys and machine tokens when the cache keeps nothing: a null store, or Rails'
# Redis store while Redis is unreachable. One caller fetches, and the callers that waited on it reuse
# what it fetched instead of each fetching in turn. Later callers in the same process reuse it too,
# for as long as the cache would have kept it.
module TokenValidatorWithoutACacheSpec
  Application = Class.new

  # Behaves as Rails' Redis store does while Redis is unreachable: every read misses, and every write
  # reports failure.
  class UnreachableRedisStore < ActiveSupport::Cache::MemoryStore
    protected

    def read_entry(_key, **) = nil

    def write_entry(_key, _entry, **) = false # rubocop:disable Naming/PredicateMethod
  end
end

RSpec.describe TokenValidator::TokenService do
  include MultiIssuerTokens

  # Each fetch takes fetch_time, so callers queued behind one another's fetches would take callers
  # times as long as one fetch.
  def callers = 10
  def fetch_time = 0.2
  def auth0_token_url = "#{auth0_issuer}oauth/token"
  def orders_api = 'https://api.example.com/orders'
  def token_service = TokenValidator::OauthTokenService.instance

  def auth0_key_set = { status: 200, body: { keys: [auth0_key.public_key.to_jwk(kid: auth0_kid, use: 'sig', alg: 'RS256')] }.to_json }
  def machine_token = { status: 200, body: { access_token: 'auth0-token', expires_in: 86_400 }.to_json }
  def machine_token_for_orders = token_service.access_token(auth0_issuer, audience: orders_api)

  # Runs the block on every caller's thread at once, and answers each result and the time they took.
  # The block must not be the first to read a key from MultiIssuerTokens::KEYS, which creates each key
  # on first read and so is not safe to read first from several threads at once.
  def all_at_once(&)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    results = Array.new(callers) { Thread.new(&) }.map(&:value)
    [results, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started]
  end

  before do
    configure_issuers
    TokenValidator::ValidatorConfig.additional_issuers = [vanity_entry, auth0_entry.merge(client_id: 'auth0-client', client_secret: 'auth0-secret')]
    described_class.clear
    allow(TokenValidator::ValidatorConfig).to receive(:logger).and_return(Logger.new(StringIO.new))
  end

  after do
    Timecop.return
    TokenValidator::ValidatorConfig.additional_issuers = []
  end

  {
    'a null store' => -> { ActiveSupport::Cache::NullStore.new },
    'a Redis store whose Redis is unreachable' => -> { TokenValidatorWithoutACacheSpec::UnreachableRedisStore.new }
  }.each do |store, new_store|
    context "with #{store}" do
      before { allow(Rails).to receive_messages(cache: new_store.call, application: TokenValidatorWithoutACacheSpec::Application.new) }

      it 'verifies tokens arriving together with one key fetch, none waiting behind another fetch' do
        stub_request(:get, auth0_jwks_url).to_return { sleep fetch_time and auth0_key_set }
        token = auth0_token

        results, elapsed = all_at_once { validates?(token) }

        expect(results).to all(be true)
        expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
        expect(elapsed).to be < callers * fetch_time / 2
      end

      it 'hands one machine token to callers asking together, with one request, none waiting behind another' do
        stub_request(:post, auth0_token_url).to_return { sleep fetch_time and machine_token }

        results, elapsed = all_at_once { machine_token_for_orders }

        expect(results.map { |token| token[:token] }).to all(eq('auth0-token'))
        expect(a_request(:post, auth0_token_url)).to have_been_made.once
        expect(elapsed).to be < callers * fetch_time / 2
      end

      it 'reuses the machine token until three minutes before it expires, then asks again' do
        stub_request(:post, auth0_token_url).to_return(machine_token)
        fetched_at = Time.now
        machine_token_for_orders

        Timecop.travel(fetched_at + 86_400 - 181) { machine_token_for_orders }
        expect(a_request(:post, auth0_token_url)).to have_been_made.once
        Timecop.travel(fetched_at + 86_400 - 179) { machine_token_for_orders }
        expect(a_request(:post, auth0_token_url)).to have_been_made.twice
      end

      it 'reuses the keys for an hour, then fetches them again' do
        stub_request(:get, auth0_jwks_url).to_return(auth0_key_set)
        fetched_at = Time.now
        validates?(auth0_token)

        Timecop.travel(fetched_at + 59.minutes) { validates?(auth0_token) }
        expect(a_request(:get, auth0_jwks_url)).to have_been_made.once
        Timecop.travel(fetched_at + 61.minutes) { validates?(auth0_token) }
        expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
      end

      it 'keeps verifying with the keys through failed refreshes for a day, and not after' do
        stub_request(:get, auth0_jwks_url).to_return(auth0_key_set, { status: 503 })
        fetched_at = Time.now
        validates?(auth0_token)

        expect(Timecop.travel(fetched_at + 23.hours) { validates?(auth0_token) }).to be true
        expect(Timecop.travel(fetched_at + 25.hours) { validates?(auth0_token) }).to be false
      end
    end
  end
end
