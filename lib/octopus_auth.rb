require "octopus_auth/version"

require "octopus_auth/configuration"

require "octopus_auth/errors"
require "octopus_auth/decorators"

require "octopus_auth/issue"
require "octopus_auth/revoke"
require "octopus_auth/queries"


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
