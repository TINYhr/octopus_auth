module OctopusAuth
  class Configuration
    attr_accessor :scopes
    attr_accessor :default_scope
    attr_accessor :token_life_time
    attr_accessor :token_length
    attr_accessor :model_class
    attr_accessor :model_readonly
    attr_accessor :access_scopes_delimiter
    attr_accessor :access_scopes_wildcard

    attr_accessor :hmac_secret
    attr_accessor :enforce_jwt_expiration
    attr_accessor :jwt_issuers
  end
end
