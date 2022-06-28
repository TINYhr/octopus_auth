require "jwt"

module OctopusAuth
  class HmacAuthenticator
    class << self
      def reset
        @jwt_params = nil
        @hmac_secret = nil
      end

      def fetch(token)
        JWT.decode(token, hmac_secret, true, jwt_params)
      rescue
        nil
      end

      private

      def jwt_params
        @jwt_params ||= if Array(OctopusAuth.configuration.jwt_issuers).empty?
          { algorithm: "HS256" }
        else
          {
            algorithm: "HS256",
            iss: OctopusAuth.configuration.jwt_issuers,
            verify_iss: true
          }
        end
      end

      def hmac_secret
        @hmac_secret ||= OctopusAuth.configuration.hmac_secret
      end
    end

    def initialize(token)
      @token = token.to_s
    end

    def authenticate
      payload = self.class.fetch(token)
      return false unless payload

      if OctopusAuth.configuration.enforce_jwt_expiration
        exp = payload.dig(0, "exp")
        return false if !exp
        return false if exp.to_i - Time.now.to_i > OctopusAuth.configuration.enforce_jwt_expiration
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
