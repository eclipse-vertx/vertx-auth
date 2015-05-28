require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.User
module VertxAuthCommon
  #  Represents an authenticate User and contains operations to authorise the user, using a permission
  #  based model.
  #  <p>
  #  Please consult the documentation for a detailed explanation.
  class User
    # @private
    # @param j_del [::VertxAuthCommon::User] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthCommon::User] the underlying java delegate
    def j_del
      @j_del
    end
    #  Does the user have the specified permission?
    # @param [String] permission the permission
    # @yield handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have the permission or `false` otherwise.
    # @return [self]
    def is_permitted(permission=nil)
      if permission.class == String && block_given?
        @j_del.java_method(:isPermitted, [Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(permission,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling is_permitted(permission)"
    end
    #  The User object will cache any roles or permissions that it knows it has to avoid hitting the
    #  underlying auth provider each time.  Use this method if you want to clear this cache.
    # @return [self]
    def clear_cache
      if !block_given?
        @j_del.java_method(:clearCache, []).call()
        return self
      end
      raise ArgumentError, "Invalid arguments when calling clear_cache()"
    end
    #  Get the underlying principal for the User. What this actually returns depends on the implementation.
    #  For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
    #  <pre>
    #    {
    #      "username", "tim"
    #    }
    #  </pre>
    # @return [Hash{String => Object}] JSON representation of the Principal
    def principal
      if !block_given?
        return @j_del.java_method(:principal, []).call() != nil ? JSON.parse(@j_del.java_method(:principal, []).call().encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling principal()"
    end
    #  Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
    #  after it has been deserialized.
    # @param [::VertxAuthCommon::AuthProvider] authProvider the AuthProvider - this must be the same type of AuthProvider that originally created the User
    # @return [void]
    def set_auth_provider(authProvider=nil)
      if authProvider.class.method_defined?(:j_del) && !block_given?
        return @j_del.java_method(:setAuthProvider, [Java::IoVertxExtAuth::AuthProvider.java_class]).call(authProvider.j_del)
      end
      raise ArgumentError, "Invalid arguments when calling set_auth_provider(authProvider)"
    end
  end
end
