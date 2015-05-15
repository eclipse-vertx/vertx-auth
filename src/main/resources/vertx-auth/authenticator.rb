require 'vertx-auth/user'
require 'vertx/buffer'
require 'vertx-auth/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.Authenticator
module VertxAuth
  class Authenticator
    # @private
    # @param j_del [::VertxAuth::Authenticator] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::Authenticator] the underlying java delegate
    def j_del
      @j_del
    end
    # @param [::VertxAuth::AuthProvider] authenticationProvider
    # @param [::VertxAuth::AuthProvider] authorisationProvider
    # @param [true,false] enableCaching
    # @param [true,false] clusterable
    # @return [::VertxAuth::Authenticator]
    def self.create(authenticationProvider=nil,authorisationProvider=nil,enableCaching=nil,clusterable=nil)
      if authenticationProvider.class.method_defined?(:j_del) && !block_given? && authorisationProvider == nil && enableCaching == nil && clusterable == nil
        return ::VertxAuth::Authenticator.new(Java::IoVertxExtAuth::Authenticator.java_method(:create, [Java::IoVertxExtAuth::AuthProvider.java_class]).call(authenticationProvider.j_del))
      elsif authenticationProvider.class.method_defined?(:j_del) && authorisationProvider.class.method_defined?(:j_del) && !block_given? && enableCaching == nil && clusterable == nil
        return ::VertxAuth::Authenticator.new(Java::IoVertxExtAuth::Authenticator.java_method(:create, [Java::IoVertxExtAuth::AuthProvider.java_class,Java::IoVertxExtAuth::AuthProvider.java_class]).call(authenticationProvider.j_del,authorisationProvider.j_del))
      elsif authenticationProvider.class.method_defined?(:j_del) && authorisationProvider.class.method_defined?(:j_del) && (enableCaching.class == TrueClass || enableCaching.class == FalseClass) && (clusterable.class == TrueClass || clusterable.class == FalseClass) && !block_given?
        return ::VertxAuth::Authenticator.new(Java::IoVertxExtAuth::Authenticator.java_method(:create, [Java::IoVertxExtAuth::AuthProvider.java_class,Java::IoVertxExtAuth::AuthProvider.java_class,Java::boolean.java_class,Java::boolean.java_class]).call(authenticationProvider.j_del,authorisationProvider.j_del,enableCaching,clusterable))
      end
      raise ArgumentError, "Invalid arguments when calling create(authenticationProvider,authorisationProvider,enableCaching,clusterable)"
    end
    # @param [Hash{String => Object}] authInfo
    # @yield 
    # @return [void]
    def authenticate(authInfo=nil)
      if authInfo.class == Hash && block_given?
        return @j_del.java_method(:authenticate, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(authInfo),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ::VertxAuth::User.new(ar.result) : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling authenticate(authInfo)"
    end
    # @param [::VertxAuth::User] user
    # @return [::Vertx::Buffer]
    def to_buffer(user=nil)
      if user.class.method_defined?(:j_del) && !block_given?
        return ::Vertx::Buffer.new(@j_del.java_method(:toBuffer, [Java::IoVertxExtAuth::User.java_class]).call(user.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling to_buffer(user)"
    end
    # @param [::Vertx::Buffer] buffer
    # @return [::VertxAuth::User]
    def from_buffer(buffer=nil)
      if buffer.class.method_defined?(:j_del) && !block_given?
        return ::VertxAuth::User.new(@j_del.java_method(:fromBuffer, [Java::IoVertxCoreBuffer::Buffer.java_class]).call(buffer.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling from_buffer(buffer)"
    end
  end
end
