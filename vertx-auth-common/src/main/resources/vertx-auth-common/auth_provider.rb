require 'vertx-auth-common/user'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.AuthProvider
module VertxAuthCommon
  # 
  #  User-facing interface for authenticating users.
  class AuthProvider
    # @private
    # @param j_del [::VertxAuthCommon::AuthProvider] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthCommon::AuthProvider] the underlying java delegate
    def j_del
      @j_del
    end
    #  Authenticate a user.
    #  <p>
    #  The first argument is a JSON object containing information for authenticating the user. What this actually contains
    #  depends on the specific implementation. In the case of a simple username/password based
    #  authentication it is likely to contain a JSON object with the following structure:
    #  <pre>
    #    {
    #      "username": "tim",
    #      "password": "mypassword"
    #    }
    #  </pre>
    #  For other types of authentication it contain different information - for example a JWT token or OAuth bearer token.
    #  <p>
    #  If the user is successfully authenticated a {::VertxAuthCommon::User} object is passed to the handler in an {AsyncResult}.
    #  The user object can then be used for authorisation.
    # @param [Hash{String => Object}] authInfo The auth information
    # @yield The result handler
    # @return [void]
    def authenticate(authInfo=nil)
      if authInfo.class == Hash && block_given?
        return @j_del.java_method(:authenticate, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(authInfo),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ::Vertx::Util::Utils.safe_create(ar.result,::VertxAuthCommon::User) : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling authenticate(authInfo)"
    end
  end
end
