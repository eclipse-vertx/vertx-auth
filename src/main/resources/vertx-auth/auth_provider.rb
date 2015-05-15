require 'vertx-auth/user'
require 'vertx/buffer'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.AuthProvider
module VertxAuth
  # 
  #  User-facing interface for authenticating users.
  class AuthProvider
    # @private
    # @param j_del [::VertxAuth::AuthProvider] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::AuthProvider] the underlying java delegate
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
    #  If the user is successfully authenticated a {::VertxAuth::User} object is passed to the handler in an .
    #  The user object can then be used for authorisation.
    # @param [Hash{String => Object}] authInfo The auth information
    # @yield The result handler
    # @return [void]
    def authenticate(authInfo=nil)
      if authInfo.class == Hash && block_given?
        return @j_del.java_method(:authenticate, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(authInfo),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ::VertxAuth::User.new(ar.result) : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling authenticate(authInfo)"
    end
    #  Reconstruct a user object from a buffer. This is typically used to recreate a user after it has been deserialized
    #  from a buffer, e.g. after being stored in a clustered session.
    # @param [::Vertx::Buffer] buffer the buffer
    # @return [::VertxAuth::User] the user
    def from_buffer(buffer=nil)
      if buffer.class.method_defined?(:j_del) && !block_given?
        return ::VertxAuth::User.new(@j_del.java_method(:fromBuffer, [Java::IoVertxCoreBuffer::Buffer.java_class]).call(buffer.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling from_buffer(buffer)"
    end
  end
end
