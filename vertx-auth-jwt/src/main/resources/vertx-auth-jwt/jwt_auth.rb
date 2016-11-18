require 'vertx-auth-common/user'
require 'vertx/vertx'
require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.jwt.JWTAuth
module VertxAuthJwt
  #  Factory interface for creating JWT based {::VertxAuthCommon::AuthProvider} instances.
  class JWTAuth < ::VertxAuthCommon::AuthProvider
    # @private
    # @param j_del [::VertxAuthJwt::JWTAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthJwt::JWTAuth] the underlying java delegate
    def j_del
      @j_del
    end
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == JWTAuth
    end
    def @@j_api_type.wrap(obj)
      JWTAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthJwt::JWTAuth.java_class
    end
    # @param [Hash{String => Object}] arg0 
    # @yield 
    # @return [void]
    def authenticate(arg0=nil)
      if arg0.class == Hash && block_given?
        return @j_del.java_method(:authenticate, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(arg0),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ::Vertx::Util::Utils.safe_create(ar.result,::VertxAuthCommon::User) : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling authenticate(#{arg0})"
    end
    #  Create a JWT auth provider
    # @param [::Vertx::Vertx] vertx the Vertx instance
    # @param [Hash{String => Object}] config the config
    # @return [::VertxAuthJwt::JWTAuth] the auth provider
    def self.create(vertx=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && config.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthJwt::JWTAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(vertx.j_del,::Vertx::Util::Utils.to_json_object(config)),::VertxAuthJwt::JWTAuth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{vertx},#{config})"
    end
    #  Generate a new JWT token.
    # @param [Hash{String => Object}] claims Json with user defined claims for a list of official claims
    # @param [Hash] options extra options for the generation
    # @return [String] JWT encoded token
    def generate_token(claims=nil,options=nil)
      if claims.class == Hash && options.class == Hash && !block_given?
        return @j_del.java_method(:generateToken, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxExtAuthJwt::JWTOptions.java_class]).call(::Vertx::Util::Utils.to_json_object(claims),Java::IoVertxExtAuthJwt::JWTOptions.new(::Vertx::Util::Utils.to_json_object(options)))
      end
      raise ArgumentError, "Invalid arguments when calling generate_token(#{claims},#{options})"
    end
  end
end
