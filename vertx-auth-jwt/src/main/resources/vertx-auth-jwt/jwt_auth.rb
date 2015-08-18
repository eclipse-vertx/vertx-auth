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
    #  Create a JWT auth provider
    # @param [::Vertx::Vertx] vertx the Vertx instance
    # @param [Hash] config the config
    # @return [::VertxAuthJwt::JWTAuth] the auth provider
    def self.create(vertx=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && !block_given? && config == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthJwt::JWTAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class]).call(vertx.j_del),::VertxAuthJwt::JWTAuth)
      elsif vertx.class.method_defined?(:j_del) && config.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthJwt::JWTAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreNet::JksOptions.java_class]).call(vertx.j_del,Java::IoVertxCoreNet::JksOptions.new(::Vertx::Util::Utils.to_json_object(config))),::VertxAuthJwt::JWTAuth)
      end
      raise ArgumentError, "Invalid arguments when calling create(vertx,config)"
    end
    #  Sets the key name in the json token where permission claims will be listed.
    # @param [String] name the key name
    # @return [self]
    def set_permissions_claim_key(name=nil)
      if name.class == String && !block_given?
        @j_del.java_method(:setPermissionsClaimKey, [Java::java.lang.String.java_class]).call(name)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_permissions_claim_key(name)"
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
