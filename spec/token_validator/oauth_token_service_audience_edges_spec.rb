# frozen_string_literal: true

require 'spec_helper'

# The edges of asking an additional issuer for a machine token by audience: an unusable audience must
# never be answered from, or fall back to, a token held for another audience, and callers asking for
# different audiences at the same moment must each get the token for their own.
RSpec.describe TokenValidator::OauthTokenService do
  include_context 'with an additional issuer'

  def entry_api = AdditionalIssuerContext::ENTRY_API
  def orders_api = AdditionalIssuerContext::ORDERS_API
  def billing_api = AdditionalIssuerContext::BILLING_API
  def extra_issuer = AdditionalIssuerContext::EXTRA_ISSUER

  def stub_token_for(audience, body)
    stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).with(body: hash_including('audience' => audience))
                                                                 .to_return(status: 200, body:)
  end

  before { use_cache }

  describe 'an audience that cannot be honoured, while other tokens are held' do
    before do
      stub_token_endpoint_echoing_audience
      service.access_token(extra_issuer)
      token_for(orders_api)
    end

    [nil, '', '   ', "\t\n", :orders, 42, ['https://api.example.com/orders'], { audience: 'x' }, Object.new].each do |audience|
      it "answers nil for #{audience.inspect[0, 40]}, not the entry's token or another audience's, and requests nothing" do
        answer = nil
        expect { answer = token_for(audience) }.not_to(change { requests_made })

        expect(answer).to be_nil
        expect(service.oauth_auth_header(extra_issuer, audience:)).to eq({})
      end
    end

    it 'treats an audience given for the primary issuer as unusable even when the primary token is cached' do
      stub_request(:post, AdditionalIssuerContext::PRIMARY_TOKEN_URL).to_return(status: 200, body: token_body('primary-token', 3600))
      service.access_token

      expect(service.access_token(AdditionalIssuerContext::PRIMARY_ISSUER, audience: orders_api)).to be_nil
      expect(a_request(:post, AdditionalIssuerContext::PRIMARY_TOKEN_URL)).to have_been_made.once
    end
  end

  describe 'when the token for one audience cannot be obtained' do
    it 'answers nil for it and never substitutes a token held for another audience' do
      stub_token_endpoint_echoing_audience
      token_for(billing_api)
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL)
        .with(body: hash_including('audience' => orders_api)).to_return(status: 503)

      expect(token_for(orders_api)).to be_nil
      expect(service.oauth_auth_header(extra_issuer, audience: orders_api)).to eq({})
      expect(token_for(billing_api)).to include(token: "token-for-#{billing_api}")
    end

    it 'does not let the audience that failed hold back the entry\'s own token' do
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL)
        .with(body: hash_including('audience' => orders_api)).to_return(status: 503)
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL)
        .with(body: hash_including('audience' => entry_api)).to_return(status: 200, body: token_body('entry-token'))

      token_for(orders_api)

      expect(service.access_token(extra_issuer)).to include(token: 'entry-token')
    end
  end

  describe 'tokens for the same audience from two additional issuers' do
    let(:second_issuer) { 'https://other-tenant.ca.auth0.com/' }
    let(:second_token_url) { 'https://other-tenant.ca.auth0.com/oauth/token' }

    before do
      TokenValidator::ValidatorConfig.additional_issuers = [
        extra_entry, extra_entry.merge(issuer_url: second_issuer, jwks_url: "#{second_issuer}.well-known/jwks.json")
      ]
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return(status: 200, body: token_body('first-issuer-token'))
      stub_request(:post, second_token_url).to_return(status: 200, body: token_body('second-issuer-token'))
    end

    it 'keeps them apart' do
      first = service.access_token(extra_issuer, audience: orders_api)
      second = service.access_token(second_issuer, audience: orders_api)

      expect([first[:token], second[:token]]).to eq(%w[first-issuer-token second-issuer-token])
      expect(service.access_token(extra_issuer, audience: orders_api)[:token]).to eq('first-issuer-token')
    end
  end

  describe 'each audience\'s token lifetime' do
    it 'is counted from that token\'s own lifetime, three minutes short, independently of the others' do
      Timecop.freeze(Time.at(1_800_000_000))
      stub_token_for(orders_api, token_body('orders-token', 600))
      stub_token_for(billing_api, token_body('billing-token', 3600))
      [orders_api, billing_api].each { |audience| token_for(audience) }

      Timecop.freeze(Time.at(1_800_000_000 + 419)) { [orders_api, billing_api].each { |audience| token_for(audience) } }
      Timecop.freeze(Time.at(1_800_000_000 + 421)) { [orders_api, billing_api].each { |audience| token_for(audience) } }

      expect(token_requests(orders_api)).to have_been_made.twice
      expect(token_requests(billing_api)).to have_been_made.once
    end
  end

  describe 'an issuer entry whose audience is a list' do
    before do
      TokenValidator::ValidatorConfig.additional_issuers = [extra_entry.merge(audience: [entry_api, "#{entry_api}/userinfo"])]
      stub_token_endpoint_echoing_audience
    end

    it 'answers nil and an empty header, and requests nothing, when no audience is named' do
      none = :unset
      expect { none = service.access_token(extra_issuer) }.not_to(change { requests_made })

      expect(none).to be_nil
      expect(service.oauth_auth_header(extra_issuer)).to eq({})
    end

    it 'still answers a token for an audience that is named' do
      expect(token_for(orders_api)).to include(token: "token-for-#{orders_api}")
    end
  end

  describe 'unusual audiences' do
    it 'tells apart two audiences that differ only by whitespace or case, and never mixes their tokens' do
      stub_token_endpoint_echoing_audience
      audiences = [orders_api, "#{orders_api} ", orders_api.upcase, "#{orders_api}\n", "#{orders_api}/"]

      tokens = audiences.map { |audience| token_for(audience)[:token] }

      expect(tokens).to eq(audiences.map { |audience| "token-for-#{audience}" })
      audiences.each { |audience| expect(token_requests(audience)).to have_been_made.once }
    end

    it 'caches a very long audience under a key of bounded length' do
      stub_token_endpoint_echoing_audience
      long_audience = "https://api.example.com/#{'a' * 100_000}"
      allow(cache).to receive(:write).and_call_original

      token_for(long_audience)

      expect(cache).to have_received(:write).with(satisfy { |key| key.length < 256 }, anything, anything).at_least(:once)
    end
  end

  describe 'callers asking for different audiences at the same moment' do
    def audiences = [orders_api, billing_api, entry_api]

    def stub_slow_endpoint
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return do |request|
        sleep 0.05
        audience = URI.decode_www_form(request.body).to_h.fetch('audience')
        { status: 200, body: token_body("token-for-#{audience}") }
      end
    end

    def ask_together(count)
      gate = Queue.new
      threads = Array.new(count) do |index|
        audience = audiences[index % audiences.size]
        Thread.new { gate.pop && [audience, token_for(audience)] }
      end
      count.times { gate << true }
      values_of(threads)
    end

    it 'gives each caller the token for its own audience, with one request per audience' do
      stub_slow_endpoint

      results = ask_together(30)

      expect(results).to all(satisfy { |audience, token| token&.fetch(:token) == "token-for-#{audience}" })
      audiences.each { |audience| expect(token_requests(audience)).to have_been_made.once }
    end

    def hold_endpoint_until_released(arrived, release)
      stub_request(:post, AdditionalIssuerContext::EXTRA_TOKEN_URL).to_return do
        arrived << :fetching
        release.pop
        { status: 200, body: token_body }
      end
    end

    it 'answers a caller with an unusable audience at once, without waiting for another audience\'s fetch' do
      arrived = Queue.new
      release = Queue.new
      hold_endpoint_until_released(arrived, release)
      fetcher = Thread.new { token_for(orders_api) }
      arrived.pop

      expect(values_of(Thread.new { [token_for(nil), token_for('')] }, timeout: 2).first).to eq([nil, nil])

      release << :go
      expect(values_of(fetcher).first).to include(token: 'extra-token')
    end
  end
end
