require "jwt"

module OctopusAuth
  class HmacAuthenticator
    def initialize(token)
      @token = token.to_s
    end

    def authenticate
      payload = fetch_payload
      return false unless payload

      yield(build_success_result(token, payload))
      true
    end

    private

    attr_reader :token

    def hmac_secret
      ENV.fetch("HMAC_SECRET")
    end

    def fetch_payload
      JWT.decode(token, hmac_secret, true, { algorithm: "HS256" })
    rescue
      nil
    end

    ResultObject = Struct.new(:token, :data)
    def build_success_result(access_token, payload)
      ResultObject.new(access_token, payload[0])
    end
  end
end
