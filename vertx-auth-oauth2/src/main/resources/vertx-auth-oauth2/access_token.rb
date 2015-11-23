require 'vertx-auth-common/user'
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
  end
end
