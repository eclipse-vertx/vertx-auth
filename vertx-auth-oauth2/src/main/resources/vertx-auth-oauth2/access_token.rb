require 'vertx-auth-common/user'
require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.oauth2.AccessToken
module VertxAuthOauth2
  #  AccessToken extension to the User interface
  class AccessToken < ::VertxAuthCommon::User
    # @private
    # @param j_del [::VertxAuthOauth2::AccessToken] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthOauth2::AccessToken] the underlying java delegate
    def j_del
      @j_del
    end
    # @param [String] arg0 
    # @yield 
    # @return [self]
    def is_authorised(arg0=nil)
      if arg0.class == String && block_given?
        @j_del.java_method(:isAuthorised, [Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(arg0,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling is_authorised(arg0)"
    end
    # @return [self]
    def clear_cache
      if !block_given?
        @j_del.java_method(:clearCache, []).call()
        return self
      end
      raise ArgumentError, "Invalid arguments when calling clear_cache()"
    end
    # @return [Hash{String => Object}]
    def principal
      if !block_given?
        return @j_del.java_method(:principal, []).call() != nil ? JSON.parse(@j_del.java_method(:principal, []).call().encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling principal()"
    end
    # @param [::VertxAuthCommon::AuthProvider] arg0 
    # @return [void]
    def set_auth_provider(arg0=nil)
      if arg0.class.method_defined?(:j_del) && !block_given?
        return @j_del.java_method(:setAuthProvider, [Java::IoVertxExtAuth::AuthProvider.java_class]).call(arg0.j_del)
      end
      raise ArgumentError, "Invalid arguments when calling set_auth_provider(arg0)"
    end
    #  Check if the access token is expired or not.
    # @return [true,false]
    def expired?
      if !block_given?
        return @j_del.java_method(:expired, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling expired?()"
    end
    #  Refresh the access token
    # @yield - The callback function returning the results.
    # @return [self]
    def refresh
      if block_given?
        @j_del.java_method(:refresh, [Java::IoVertxCore::Handler.java_class]).call((Proc.new { |ar| yield(ar.failed ? ar.cause : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling refresh()"
    end
    #  Revoke access or refresh token
    # @param [String] token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
    # @yield - The callback function returning the results.
    # @return [self]
    def revoke(token_type=nil)
      if token_type.class == String && block_given?
        @j_del.java_method(:revoke, [Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(token_type,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling revoke(token_type)"
    end
    #  Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
    #  available on all providers.
    # @yield - The callback function returning the results.
    # @return [self]
    def logout
      if block_given?
        @j_del.java_method(:logout, [Java::IoVertxCore::Handler.java_class]).call((Proc.new { |ar| yield(ar.failed ? ar.cause : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling logout()"
    end
  end
end
