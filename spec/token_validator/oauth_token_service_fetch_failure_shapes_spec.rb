# frozen_string_literal: true

require 'spec_helper'

# An additional issuer's machine token or signing keys that cannot be fetched or used is a clean
# answer -- no token and an empty header, or no keys -- never an exception, whatever the way it went
# wrong. The second call in each example also shows the failure is held back rather than repeated.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  let(:token_url) { AdditionalIssuerContext::EXTRA_TOKEN_URL }
  let(:jwks_url) { AdditionalIssuerContext::EXTRA_JWKS_URL }
  let(:orders_api) { AdditionalIssuerContext::ORDERS_API }

  before { use_cache }

  connection_and_protocol_failures = {
    'a refused connection' => ->(stub) { stub.to_raise(Errno::ECONNREFUSED) },
    'a reset connection' => ->(stub) { stub.to_raise(Errno::ECONNRESET) },
    'a timed out connection' => ->(stub) { stub.to_raise(Errno::ETIMEDOUT) },
    'an unreachable host' => ->(stub) { stub.to_raise(Errno::EHOSTUNREACH) },
    'an unreachable network' => ->(stub) { stub.to_raise(Errno::ENETUNREACH) },
    'a broken pipe' => ->(stub) { stub.to_raise(Errno::EPIPE) },
    'a DNS failure' => ->(stub) { stub.to_raise(SocketError) },
    'a TLS failure' => ->(stub) { stub.to_raise(OpenSSL::SSL::SSLError) },
    'a connection closed mid-response' => ->(stub) { stub.to_raise(EOFError) },
    'an I/O error' => ->(stub) { stub.to_raise(IOError) },
    'a connect timeout' => ->(stub) { stub.to_raise(Net::OpenTimeout) },
    'a read timeout' => ->(stub) { stub.to_raise(Net::ReadTimeout) },
    'a timeout' => :to_timeout.to_proc,
    'a 429 response' => ->(stub) { stub.to_return(status: 429) },
    'a 503 response' => ->(stub) { stub.to_return(status: 503) }
  }

  # What the HTTP library raises, unwrapped, for a response that is not valid HTTP or whose compressed
  # body is corrupt.
  malformed_response_failures = {
    'a malformed status line' => ->(stub) { stub.to_raise(Net::HTTPBadResponse) },
    'a malformed header' => ->(stub) { stub.to_raise(Net::HTTPHeaderSyntaxError) },
    'a protocol error' => ->(stub) { stub.to_raise(Net::ProtocolError) },
    'a corrupt compressed body' => ->(stub) { stub.to_raise(Zlib::DataError) },
    'a truncated compressed body' => ->(stub) { stub.to_raise(Zlib::BufError) },
    'a compressed body with a bad header' => ->(stub) { stub.to_raise(Zlib::GzipFile::Error) }
  }

  describe 'a machine token that cannot be fetched' do
    connection_and_protocol_failures.merge(malformed_response_failures).each do |failure, stub_it|
      it "answers nil and an empty header for #{failure}, and does not ask again within the backoff" do
        stub_it.call(stub_request(:post, token_url))

        expect(token_for(orders_api)).to be_nil
        expect(service.oauth_auth_header(AdditionalIssuerContext::EXTRA_ISSUER, audience: orders_api)).to eq({})
        expect(token_requests(orders_api)).to have_been_made.once
      end
    end

    {
      'that is empty' => '',
      'that is not JSON' => '<html>maintenance</html>',
      'that is JSON null' => 'null',
      'that is a JSON list' => '[]',
      'that is a JSON string' => '"token"',
      'that is a JSON number' => '42',
      'that is nested far too deeply' => "#{'[' * 200}#{']' * 200}",
      'that is an object with no token' => '{"expires_in":3600}',
      'whose token is null' => '{"access_token":null,"expires_in":3600}',
      'whose token is empty' => '{"access_token":"","expires_in":3600}',
      'whose token is a number' => '{"access_token":5,"expires_in":3600}',
      'whose token is a list' => '{"access_token":["t"],"expires_in":3600}',
      'with no lifetime' => '{"access_token":"t"}',
      'whose lifetime is null' => '{"access_token":"t","expires_in":null}',
      'whose lifetime is a string' => '{"access_token":"t","expires_in":"3600"}',
      'whose lifetime is a boolean' => '{"access_token":"t","expires_in":true}'
    }.each do |body_kind, body|
      it "answers nil for a response #{body_kind}, and does not ask again within the backoff" do
        stub_request(:post, token_url).to_return(status: 200, body:)

        2.times { expect(token_for(orders_api)).to be_nil }

        expect(token_requests(orders_api)).to have_been_made.once
      end
    end

    it 'answers nil for a redirect, which a token request is never sent on' do
      stub_request(:post, token_url).to_return(status: 302, headers: { 'Location' => 'https://elsewhere.example.com/' })

      expect(token_for(orders_api)).to be_nil
      expect(a_request(:post, 'https://elsewhere.example.com/')).not_to have_been_made
    end

    it 'logs the failure without the response body or the client secret' do
      stub_request(:post, token_url).to_return(status: 200, body: '{"echo":"extra-secret super-secret-body"}')

      token_for(orders_api)

      expect(log_lines.string).to include('Could not fetch').and(satisfy { |text| !text.include?('super-secret-body') && !text.include?('extra-secret') })
    end
  end

  describe 'signing keys that cannot be fetched' do
    connection_and_protocol_failures.merge(malformed_response_failures).each do |failure, stub_it|
      it "answers no keys for #{failure}, and does not ask again within the backoff" do
        stub_it.call(stub_request(:get, jwks_url))

        2.times { expect(extra_keys).to be_nil }

        expect(key_requests).to have_been_made.once
      end
    end

    it 'answers no keys when a redirect leads to a failing endpoint' do
      stub_request(:get, jwks_url).to_return(status: 302, headers: { 'Location' => 'https://elsewhere.example.com/keys' })
      stub_request(:get, 'https://elsewhere.example.com/keys').to_return(status: 503)

      expect(extra_keys).to be_nil
    end

    {
      'that is empty' => '',
      'that is not JSON' => '<html>maintenance</html>',
      'that is JSON null' => 'null',
      'that is a JSON list' => '[]',
      'that is nested far too deeply' => "#{'[' * 200}#{']' * 200}",
      'that is an object with no keys' => '{}',
      'whose keys are null' => '{"keys":null}',
      'whose keys are an object' => '{"keys":{}}',
      'whose keys are an empty list' => '{"keys":[]}',
      'whose keys are all null' => '{"keys":[null,null]}',
      'whose keys are not objects' => '{"keys":[1,"x",[]]}',
      'whose keys are empty objects' => '{"keys":[{}]}',
      'whose key has no modulus' => '{"keys":[{"kty":"RSA","e":"AQAB","kid":"a"}]}',
      'whose key has an unusable modulus' => '{"keys":[{"kty":"RSA","e":"AQAB","n":"!!!","kid":"a"}]}',
      'whose key has an unknown curve' => '{"keys":[{"kty":"EC","crv":"P-999","x":"AA","y":"AA","kid":"a"}]}',
      'whose key has a non-string type' => '{"keys":[{"kty":5,"kid":"a"}]}'
    }.each do |body_kind, body|
      it "answers no keys for a response #{body_kind}, without raising" do
        stub_request(:get, jwks_url).to_return(status: 200, body:)

        expect(extra_keys).to be_nil
      end
    end

    it 'uses the usable keys of a set that also holds keys of every unusable kind' do
      body = { keys: [nil, 1, {}, { kty: 'RSA', e: 'AQAB', kid: 'broken' }, jwk('good')] }.to_json
      stub_request(:get, jwks_url).to_return(status: 200, body:)

      expect(kids_of(extra_keys)).to eq(['good'])
    end
  end

  describe 'a cached key set, when its refresh gets each kind of unusable answer' do
    it 'keeps serving the cached set for every one of them' do
      stub_request(:get, jwks_url).to_return(key_set_response('a'))
      extra_keys
      unusable_answers = ['', 'null', '[]', '{"keys":[]}', '{"keys":[{}]}', '<html></html>']

      unusable_answers.each do |body|
        stub_request(:get, jwks_url).to_return(status: 200, body:)
        Timecop.travel(Time.now + 2.hours)
        expect(kids_of(extra_keys)).to eq(['a'])
      end
    end
  end
end
