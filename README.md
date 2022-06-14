[![Build Status](https://travis-ci.org/TINYhr/octopus_auth.svg?branch=master)](https://travis-ci.org/TINYhr/octopus_auth)

[![Gem Version](https://badge.fury.io/rb/octopus_auth.svg)](https://badge.fury.io/rb/octopus_auth)

# OctopusAuth

OctopusAuth provides mechanism to:

* Manage, issue, revoke `access_token`
* Authenticate `access_token`

OctopusAuth excludes data `model`, we could use any orm to persist `access_token`, just make sure it follows interface.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'octopus_auth'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install octopus_auth

## Usage

Configure OctopusAuth before use:

```
OctopusAuth.configure do |config|
  config.scopes           = [:system, :company, :user].freeze
  config.default_scope    = :user
  config.token_life_time  = 2.hours
  config.token_length     = 20
  config.model_class      = AccessToken
  config.model_readonly   = true
end

```

Currently, model class `AccessToken` must be an ActiveRecord sub class. with attributes:
```
:id,
:token,
:created_at,
:issued_at,
:active,
:expires_at,
:expired_at,
:scope,
:owner_id,
:owner_type,
:creator_id
```

### Manage token

`OctopusAuth` support issue, revoke and query access token:

```
access_token = OctopusAuth::Issue.new(:company, 'Company', company_id, user_id).execute
access_token = OctopusAuth::Revoke.new(token_as_text).execute
access_tokens = OctopusAuth::Queries::ByScope.new(scope, owner_type, owner_id).execute
```

`token` needs

* A `scope` defined in `config.scopes`, i.e. `:company`
* An optional target for that scope, like `('Company', company_id)` We could use polymorphic or any kind of relationship, it's not `OctopusAuth` duty.
* And an creator, which should be `user_id` of use in system.

`OctopusAuth` allow users define their own `AccessToken` model and detaches from it. So `OctopusAuth` don't know anything about token relationships which rely on each business.
Every returned token are `OctopusAuth::Decorators::Default` for less rely on `ActiveRecord`

### Authenticate token

`OctopusAuth::Authenticator#authenticate` returns `true`/`false`.
If true, mean success, block will be called with `success_result` object as below.

```
OctopusAuth::Authenticator.new(token, scope).authenticate do |success_result|
    track(success_result.token,
        success_result.scope,
        success_result.owner_type,
        success_result.owner_id)
end
```

### Generate model

TODO: Write rails/rake tasks to generator model migration

## Authentication using JWT HMAC

For now, using JWT HMAC SHA-256 to authenticate, payload is not decided yet, and yield back to app to verify. 

HMAC secret is set by `HMAC_SECRET` environment variable, client must have this secret to create token. `OctopusAuth` doesn't enforce, but token expiration time (`exp` claim) should be enable on client side for security reason. 

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/octopus_auth. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the OctopusAuth project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/octopus_auth/blob/master/CODE_OF_CONDUCT.md).
