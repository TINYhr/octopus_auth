require "jwt"

module OctopusAuth
  class Authenticator
    def initialize(token, scope = nil)
      @token = token.to_s
      @scope = scope || OctopusAuth.configuration.default_scope
    end

    def authenticate
      if parsed_payload
        yield(build_success_result(token, parsed_payload)) if block_given?
        true
      else
        false
      end
    end

    private

    attr_reader :token

    def hmac_secret
      ENV.fetch("HMAC_SECRET")
    end

    def parsed_payload
      JWT.decode(token, hmac_secret, true, { algorithm: "HS256" })
    rescue
      nil
    end

    ResultObject = Struct.new(:token, :data)
    def build_success_result(access_token, parsed_payload)
      ResultObject.new(access_token, parsed_payload[0])
    end
  end
end
