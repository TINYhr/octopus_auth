require 'spec_helper'

RSpec.describe OctopusAuth::HmacAuthenticator do
  describe "#authenticate" do
    subject { described_class.new(token).authenticate }

    let(:payload) do
      {
        data: "__SAMPLE_DATA__",
      }
    end

    before do
      @prev_hmac_secret = ENV["HMAC_SECRET"]
      ENV["HMAC_SECRET"] = "__TEST_HMAC_SECRET__"
    end

    after do
      ENV["HMAC_SECRET"] = @prev_hmac_secret
    end

    context "JWT failed to verify" do
      let(:token) { "__INVALID_TOKEN__" }

      it { is_expected.to eq(false) }

      it "does not yield payload" do
        expect do |block|
          described_class.new(token).authenticate(&block)
        end.not_to yield_control
      end
    end

    context "JWT verify succeed" do
      # let(:token) { JWT.encode(payload, "__TEST_HMAC_SECRET__", "HS256") }
      let(:token) do
        "eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiX19TQU1QTEVfREFUQV9fIn0."\
          "rFgKwv-fYJP7R0jRaluqmn-PH1p5-YiPZ83riAQ80dw"
      end

      it "returns true" do
        expect(described_class.new(token).authenticate).to eq(true)
      end

      it "yields payload" do
        expect do |block|
          described_class.new(token).authenticate(&block)
        end.to yield_control

        described_class.new(token).authenticate do |result|
          expect(result.token).to eq(token)
          expect(result.data).to eq({"data" => "__SAMPLE_DATA__"})
        end
      end
    end
  end
end
