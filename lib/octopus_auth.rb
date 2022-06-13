require "octopus_auth/version"

require "octopus_auth/configuration"

require "octopus_auth/errors"
require "octopus_auth/decorators"

require "octopus_auth/issue"
require "octopus_auth/revoke"
require "octopus_auth/queries"

require "octopus_auth/authenticator"
require "octopus_auth/hmac_authenticator"
require "octopus_auth/access_scope_validator"

module OctopusAuth
  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration ||= OctopusAuth::Configuration.new
    yield(configuration)
  end

  def self.reset
    self.configuration = OctopusAuth::Configuration.new
  end
end
