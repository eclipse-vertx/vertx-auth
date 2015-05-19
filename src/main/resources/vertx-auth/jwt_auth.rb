require 'vertx-auth/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.jwt.JWTAuth
module VertxAuth
  #  Factory interface for creating JWT based {::VertxAuth::AuthProvider} instances.
  class JWTAuth < ::VertxAuth::AuthProvider
    # @private
    # @param j_del [::VertxAuth::JWTAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::JWTAuth] the underlying java delegate
    def j_del
      @j_del
    end
    # @param [::Vertx::Vertx] vertx
    # @param [Hash{String => Object}] config
    # @return [::VertxAuth::JWTAuth]
    def self.create(vertx=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && config.class == Hash && !block_given?
        return ::VertxAuth::JWTAuth.new(Java::IoVertxExtAuthJwt::JWTAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(vertx.j_del,::Vertx::Util::Utils.to_json_object(config)))
      end
      raise ArgumentError, "Invalid arguments when calling create(vertx,config)"
    end
    # @param [Hash{String => Object}] payload
    # @param [Hash] options
    # @yield 
    # @return [self]
    def generate_token(payload=nil,options=nil)
      if payload.class == Hash && options.class == Hash && block_given?
        @j_del.java_method(:generateToken, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxExtAuthJwt::JWTOptions.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(payload),Java::IoVertxExtAuthJwt::JWTOptions.new(::Vertx::Util::Utils.to_json_object(options)),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling generate_token(payload,options)"
    end
  end
end
