require 'spec_helper'

RSpec.describe OctopusAuth::HmacAuthenticator do
  describe "#authenticate" do
    subject { described_class.new(token).authenticate }

    context "JWT failed to verify" do
      let(:token) { "" }

      it { is_expected.to eq(false) }

      it { is_expected.not_to yield_control }
    end

    context "JWT verify succeed" do
      let(:token) { "" }

      it { is_expected.to eq(true) }

      it "yields payload" do
        described_class.new(token).authenticate do |result|
          expect(result.token).to eq(token)
          expect(result.data).to eq({"data" => "__SAMPLE_DATA__"})
        end
      end
    end
  end
end
