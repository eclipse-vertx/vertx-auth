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
    # @param [Hash{String => Object}] config
    # @return [::VertxAuth::JWTAuth]
    def self.create(config=nil)
      if config.class == Hash && !block_given?
        return ::VertxAuth::JWTAuth.new(Java::IoVertxExtAuthJwt::JWTAuth.java_method(:create, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(config)))
      end
      raise ArgumentError, "Invalid arguments when calling create(config)"
    end
    #  Generate a new JWT token.
    # @param [Hash{String => Object}] claims Json with user defined claims for a list of official claims
    # @param [Hash] options extra options for the generation
    # @return [String] JWT encoded token
    def generate_token(claims=nil,options=nil)
      if claims.class == Hash && options.class == Hash && !block_given?
        return @j_del.java_method(:generateToken, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxExtAuthJwt::JWTOptions.java_class]).call(::Vertx::Util::Utils.to_json_object(claims),Java::IoVertxExtAuthJwt::JWTOptions.new(::Vertx::Util::Utils.to_json_object(options)))
      end
      raise ArgumentError, "Invalid arguments when calling generate_token(claims,options)"
    end
  end
end
