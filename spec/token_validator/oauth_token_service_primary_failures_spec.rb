# frozen_string_literal: true

require 'spec_helper'

# What the primary issuer's machine-token and signing-key fetches do when something goes wrong: the
# answer or exception for each kind of failure, and whether the next call asks again. Every row below
# is how the primary issuer has always behaved, including the failures that raise and the one that
# is cached; it changes only if the hardening applied to additional issuers is deliberately extended
# to the primary one.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  let(:primary_issuer) { AdditionalIssuerContext::PRIMARY_ISSUER }
  let(:token_url) { AdditionalIssuerContext::PRIMARY_TOKEN_URL }
  let(:jwks_url) { AdditionalIssuerContext::PRIMARY_JWKS_URL }

  before { use_cache }

  # Failures the HTTP client wraps in its own exception, or that the primary path rescues itself.
  answered_with_nothing = {
    'a 400 response' => ->(stub) { stub.to_return(status: 400) },
    'a 401 response' => ->(stub) { stub.to_return(status: 401, body: '{"error":"invalid_client"}') },
    'a 404 response' => ->(stub) { stub.to_return(status: 404) },
    'a 429 response' => ->(stub) { stub.to_return(status: 429) },
    'a 500 response' => ->(stub) { stub.to_return(status: 500) },
    'a 503 response' => ->(stub) { stub.to_return(status: 503) },
    'a timeout' => :to_timeout.to_proc,
    'a connect timeout' => ->(stub) { stub.to_raise(Net::OpenTimeout) },
    'a read timeout' => ->(stub) { stub.to_raise(Net::ReadTimeout) },
    'a refused connection' => ->(stub) { stub.to_raise(Errno::ECONNREFUSED) },
    'a timed out connection' => ->(stub) { stub.to_raise(Errno::ETIMEDOUT) },
    'a connection closed mid-response' => ->(stub) { stub.to_raise(EOFError) }
  }

  # Failures that reach the caller as the exception they are.
  raised_to_the_caller = {
    'a reset connection' => [Errno::ECONNRESET, ->(stub) { stub.to_raise(Errno::ECONNRESET) }],
    'an unreachable host' => [Errno::EHOSTUNREACH, ->(stub) { stub.to_raise(Errno::EHOSTUNREACH) }],
    'a broken pipe' => [Errno::EPIPE, ->(stub) { stub.to_raise(Errno::EPIPE) }],
    'a DNS failure' => [SocketError, ->(stub) { stub.to_raise(SocketError) }],
    'a TLS failure' => [OpenSSL::SSL::SSLError, ->(stub) { stub.to_raise(OpenSSL::SSL::SSLError) }],
    'an I/O error' => [IOError, ->(stub) { stub.to_raise(IOError) }],
    'a malformed status line' => [Net::HTTPBadResponse, ->(stub) { stub.to_raise(Net::HTTPBadResponse) }],
    'a malformed header' => [Net::HTTPHeaderSyntaxError, ->(stub) { stub.to_raise(Net::HTTPHeaderSyntaxError) }],
    'a protocol error' => [Net::ProtocolError, ->(stub) { stub.to_raise(Net::ProtocolError) }],
    'a corrupt compressed body' => [Zlib::DataError, ->(stub) { stub.to_raise(Zlib::DataError) }]
  }

  describe 'the machine token' do
    answered_with_nothing.each do |failure, stub_it|
      it "answers nil for #{failure}, and asks again on every call" do
        stub_it.call(stub_request(:post, token_url))

        answers = Array.new(3) { service.access_token }

        expect(answers).to eq([nil, nil, nil])
        expect(a_request(:post, token_url)).to have_been_made.times(3)
      end
    end

    raised_to_the_caller.each do |failure, (error, stub_it)|
      it "raises #{error} for #{failure}, and asks again on every call" do
        stub_it.call(stub_request(:post, token_url))

        3.times { expect { service.access_token }.to raise_error(error) }

        expect(a_request(:post, token_url)).to have_been_made.times(3)
      end
    end

    {
      'that is empty' => ['', JSON::ParserError],
      'that is not JSON' => ['<html>maintenance</html>', JSON::ParserError],
      'that is JSON null' => ['null', NoMethodError],
      'that is a JSON list' => ['[]', TypeError],
      'that is a JSON object without a lifetime' => ['{"access_token":"t"}', TypeError],
      'that is an empty JSON object' => ['{}', TypeError],
      'whose lifetime is a string' => ['{"access_token":"t","expires_in":"3600"}', TypeError]
    }.each do |body_kind, (body, error)|
      it "raises #{error} for a response #{body_kind}" do
        stub_request(:post, token_url).to_return(status: 200, body:)

        expect { service.access_token }.to raise_error(error)
      end
    end

    it 'hands out and caches a response that has a lifetime but no token' do
      stub_request(:post, token_url).to_return(status: 200, body: { access_token: nil, expires_in: 3600 }.to_json)

      2.times { expect(service.access_token).to include(token: nil, expires_in: 3600) }

      expect(a_request(:post, token_url)).to have_been_made.once
    end

    context 'with a lifetime shorter than the three minutes held back' do
      let(:short_lived) { { status: 200, body: { access_token: 't', expires_in: 100 }.to_json } }

      around do |example|
        original = ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time
        example.run
      ensure
        ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = original
      end

      it 'raises when the cache rejects a negative expiry' do
        ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = true
        stub_request(:post, token_url).to_return(short_lived)

        expect { service.access_token }.to raise_error(ArgumentError, /expiration time is invalid/)
      end

      it 'caches the token with no expiry when the cache ignores a negative one' do
        ActiveSupport::Cache::Store.raise_on_invalid_cache_expiration_time = false
        stub_request(:post, token_url).to_return(short_lived)
        service.access_token

        Timecop.travel(Time.now + 3.days) { expect(service.access_token).to include(token: 't') }

        expect(a_request(:post, token_url)).to have_been_made.once
      end
    end
  end

  describe 'the signing keys' do
    answered_with_nothing.each do |failure, stub_it|
      it "answers nil for #{failure}, and keeps answering nil from the cache without asking again" do
        stub_it.call(stub_request(:get, jwks_url))

        answers = Array.new(3) { service.signing_key }

        expect(answers).to eq([nil, nil, nil])
        expect(a_request(:get, jwks_url)).to have_been_made.once
      end
    end

    raised_to_the_caller.each do |failure, (error, stub_it)|
      it "raises #{error} for #{failure}, and asks again on every call" do
        stub_it.call(stub_request(:get, jwks_url))

        3.times { expect { service.signing_key }.to raise_error(error) }

        expect(a_request(:get, jwks_url)).to have_been_made.times(3)
      end
    end

    {
      'that is empty' => ['', JSON::ParserError],
      'that is not JSON' => ['<html>maintenance</html>', JSON::ParserError],
      'that is JSON null' => ['null', NoMethodError],
      'that is a JSON list' => ['[]', NoMethodError]
    }.each do |body_kind, (body, error)|
      it "raises #{error} for a response #{body_kind}" do
        stub_request(:get, jwks_url).to_return(status: 200, body:)

        expect { service.signing_key }.to raise_error(error)
      end
    end
  end

  describe 'verifying tokens through an outage of the key endpoint' do
    include_context 'with signed tokens'

    it 'loses the cached keys to the first token naming an unknown key id, and refuses valid tokens until the endpoint is back' do
      stub_request(:get, jwks_url).to_return(primary_key_set)
      expect(validates?(primary_token)).to be(true)

      stub_request(:get, jwks_url).to_return(status: 503)
      expect(validates?(primary_token(kid: 'no-such-kid'))).to be(false)

      expect(validates?(primary_token)).to be(false)
    end
  end
end
