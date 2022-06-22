require "jwt"

module OctopusAuth
  class HmacAuthenticator
    class << self
      def jwt_params
        @jwt_params ||= if Array(OctopusAuth.configuration.jwt_issuers).empty?
          { algorithm: "HS256" }
        else
          { algorithm: "HS256", iss: OctopusAuth.configuration.jwt_issuers }
        end
      end

      def hmac_secret
        @hmac_secret ||= ENV.fetch("HMAC_SECRET")
      end

      def fetch(token)
        JWT.decode(token, hmac_secret, true, jwt_params)
      rescue
        nil
      end
    end

    def initialize(token)
      @token = token.to_s
    end

    def authenticate
      payload = self.class.fetch(token)
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

    ResultObject = Struct.new(:token, :data)
    def build_success_result(access_token, payload)
      ResultObject.new(access_token, payload[0])
    end
  end
end
