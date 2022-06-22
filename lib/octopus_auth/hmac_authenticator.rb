require "jwt"

module OctopusAuth
  class HmacAuthenticator
    def initialize(token)
      @token = token.to_s
    end

    def authenticate
      payload = fetch_payload
      return false unless payload

      if OctopusAuth.configuration.enforce_jwt_expiration
        && !payload.dig(1, :exp)
          return false
      end

      yield(build_success_result(token, payload)) if block_given?
      true
    end

    private

    attr_reader :token

    def hmac_secret
      ENV.fetch("HMAC_SECRET")
    end

    def fetch_payload
      JWT.decode(token, hmac_secret, true, jwt_params)
    rescue
      nil
    end

    def jwt_params
      return { algorithm: "HS256" } if Array(OctopusAuth.configuration.jwt_issuers).empty?

      { algorithm: "HS256", iss: OctopusAuth.configuration.jwt_issuers }
    end

    ResultObject = Struct.new(:token, :data)
    def build_success_result(access_token, payload)
      ResultObject.new(access_token, payload[0])
    end
  end
end
