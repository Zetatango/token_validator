# frozen_string_literal: true

require 'spec_helper'

# Verifying an additional issuer's token when its key set misbehaves, and when a token names a key id
# the cached set lacks. Every such token is refused -- false, never an exception -- and a stranger's
# token can neither make every request a key fetch nor cost valid callers the keys already cached.
RSpec.describe TokenValidator::TokenService do
  include MultiIssuerTokens

  def next_auth0_key = MultiIssuerTokens::KEYS[:auth0_next]

  def key_set_body(*pairs)
    { keys: pairs.map { |key, kid| key.public_key.to_jwk(kid:, use: 'sig', alg: 'RS256') } }.to_json
  end

  def auth0_key_set(*pairs)
    { status: 200, body: key_set_body(*pairs) }
  end

  before do
    configure_issuers
    described_class.clear
    allow(TokenValidator::ValidatorConfig).to receive(:logger).and_return(Logger.new(StringIO.new))
  end

  after do
    Timecop.return
    TokenValidator::ValidatorConfig.additional_issuers = []
  end

  describe 'a key set that cannot be fetched or used' do
    {
      'a DNS failure' => ->(stub) { stub.to_raise(SocketError) },
      'a connection reset' => ->(stub) { stub.to_raise(Errno::ECONNRESET) },
      'a body that is not JSON' => ->(stub) { stub.to_return(status: 200, body: '<html>maintenance</html>') },
      'a body that is a JSON list' => ->(stub) { stub.to_return(status: 200, body: '[]') },
      'a body that is JSON null' => ->(stub) { stub.to_return(status: 200, body: 'null') },
      'a body with no keys' => ->(stub) { stub.to_return(status: 200, body: '{}') }
    }.each do |failure, respond|
      it "refuses the token, without raising, for #{failure}" do
        instance_exec(stub_request(:get, auth0_jwks_url), &respond)

        expect(validates?(auth0_token)).to be false
      end
    end

    it 'refuses a token naming a key published in a shape that cannot verify, and still verifies the others' do
      bad_key = { kty: 'RSA', kid: 'broken-kid' }
      body = { keys: [bad_key, auth0_key.public_key.to_jwk(kid: auth0_kid, use: 'sig', alg: 'RS256')] }.to_json
      stub_request(:get, auth0_jwks_url).to_return(status: 200, body:)

      expect(validates?(auth0_token(kid: 'broken-kid'))).to be false
      expect(validates?(auth0_token)).to be true
    end
  end

  describe 'a token naming a key id the cached set lacks' do
    before { with_cache }

    it 'refetches once for a run of such tokens, and refuses them all' do
      stub_request(:get, auth0_jwks_url).to_return(auth0_key_set([auth0_key, auth0_kid]))

      results = %w[junk-1 junk-2 junk-3].map { |kid| validates?(auth0_token(kid:)) }

      expect(results).to eq([false, false, false])
      expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
    end

    it 'cannot cost valid callers the cached keys while the key endpoint is failing' do
      stub_request(:get, auth0_jwks_url).to_return(auth0_key_set([auth0_key, auth0_kid]), { status: 503 })
      validates?(auth0_token)

      expect(validates?(auth0_token(kid: 'junk'))).to be false
      expect(validates?(auth0_token)).to be true
    end

    it 'accepts a token signed with a key the issuer has just rotated in' do
      stub_request(:get, auth0_jwks_url)
        .to_return(auth0_key_set([auth0_key, auth0_kid]), auth0_key_set([auth0_key, auth0_kid], [next_auth0_key, 'auth0-next']))
      validates?(auth0_token)

      expect(validates?(auth0_token(key: next_auth0_key, kid: 'auth0-next'))).to be true
    end

    it 'still accepts a rotated key once the cooldown a stranger started has passed' do
      stub_request(:get, auth0_jwks_url)
        .to_return(auth0_key_set([auth0_key, auth0_kid]), auth0_key_set([auth0_key, auth0_kid]),
                   auth0_key_set([auth0_key, auth0_kid], [next_auth0_key, 'auth0-next']))
      validates?(auth0_token(kid: 'junk'))

      Timecop.travel(Time.now + 61.seconds)

      expect(validates?(auth0_token(key: next_auth0_key, kid: 'auth0-next'))).to be true
    end

    it 'leaves the primary issuer\'s keys alone' do
      stub_every_issuer
      validates?(roadrunner_token)

      validates?(auth0_token(kid: 'junk'))

      expect(validates?(roadrunner_token)).to be true
      expect(a_request(:get, primary_jwks_url)).to have_been_made.once
    end
  end

  it 'fetches twice for such a token without a cache, as before' do
    stub_request(:get, auth0_jwks_url).to_return(auth0_key_set([auth0_key, auth0_kid]))

    validates?(auth0_token(kid: 'junk'))

    expect(a_request(:get, auth0_jwks_url)).to have_been_made.twice
  end
end
