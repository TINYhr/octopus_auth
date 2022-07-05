require 'spec_helper'

RSpec.describe OctopusAuth::HmacAuthenticator do
  describe "#authenticate" do
    subject { described_class.new(token).authenticate }

    let(:payload) do
      {
        data: "__SAMPLE_DATA__",
      }
    end

    describe "without iss or exp" do
      before do
        OctopusAuth.reset
        described_class.reset
        OctopusAuth.configure do |config|
          config.hmac_secret = "__TEST_HMAC_SECRET__"
        end
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

        it { is_expected.to eq(true) }

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

    describe "with iss" do
      before do
        OctopusAuth.reset
        described_class.reset
        OctopusAuth.configure do |config|
          config.hmac_secret = "__TEST_HMAC_SECRET__"
          config.jwt_issuers = ["Service A", "Service B"]
        end
      end

      context "no iss" do
        let(:token) { JWT.encode(payload, "__TEST_HMAC_SECRET__", "HS256") }

        it { is_expected.to eq(false) }
      end

      context "valid iss" do
        let(:token) do
          JWT.encode(
            payload.merge({ iss: "Service A" }),
            "__TEST_HMAC_SECRET__",
            "HS256"
          )
        end

        it { is_expected.to eq(true) }
      end

      context "invalid iss" do
        let(:token) do
          JWT.encode(
            payload.merge({ iss: "Service C" }),
            "__TEST_HMAC_SECRET__",
            "HS256"
          )
        end

        it { is_expected.to eq(false) }
      end
    end

    describe "with exp" do
      before do
        OctopusAuth.reset
        described_class.reset
        OctopusAuth.configure do |config|
          config.hmac_secret = "__TEST_HMAC_SECRET__"
          config.enforce_jwt_expiration = 3600
        end
      end

      context "no exp" do
        let(:token) { JWT.encode(payload, "__TEST_HMAC_SECRET__", "HS256") }

        it { is_expected.to eq(false) }
      end

      context "valid exp" do
        let(:token) do
          JWT.encode(
            payload.merge({ exp: Time.now.to_i + 1800 }),
            "__TEST_HMAC_SECRET__",
            "HS256"
          )
        end

        it { is_expected.to eq(true) }
      end

      context "expired exp" do
        let(:token) do
          JWT.encode(
            payload.merge({ exp: Time.now.to_i - 18 }),
            "__TEST_HMAC_SECRET__",
            "HS256"
          )
        end

        it { is_expected.to eq(false) }
      end

      context "exp too long" do
        let(:token) do
          JWT.encode(
            payload.merge({ exp: Time.now.to_i + 3601 }),
            "__TEST_HMAC_SECRET__",
            "HS256"
          )
        end

        it { is_expected.to eq(false) }
      end
    end
  end
end
