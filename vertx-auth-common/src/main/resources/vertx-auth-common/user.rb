require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.User
module VertxAuthCommon
  #  Represents an authenticates User and contains operations to authorise the user.
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
    #  Is the user authorised to
    # @param [String] authority the authority - what this really means is determined by the specific implementation. It might represent a permission to access a resource e.g. `printers:printer34` or it might represent authority to a role in a roles based model, e.g. `role:admin`.
    # @yield handler that will be called with an {AsyncResult} containing the value `true` if the they has the authority or `false` otherwise.
    # @return [self]
    def is_authorised(authority=nil)
      if authority.class == String && block_given?
        @j_del.java_method(:isAuthorised, [Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(authority,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling is_authorised(authority)"
    end
    #  The User object will cache any authorities that it knows it has to avoid hitting the
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
