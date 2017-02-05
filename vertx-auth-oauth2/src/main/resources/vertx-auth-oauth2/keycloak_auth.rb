require 'vertx/vertx'
require 'vertx-auth-oauth2/o_auth2_auth'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.oauth2.providers.KeycloakAuth
module VertxAuthOauth2
  #  Simplified factory to create an  for Keycloak.
  class KeycloakAuth
    # @private
    # @param j_del [::VertxAuthOauth2::KeycloakAuth] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthOauth2::KeycloakAuth] the underlying java delegate
    def j_del
      @j_del
    end
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == KeycloakAuth
    end
    def @@j_api_type.wrap(obj)
      KeycloakAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthOauth2Providers::KeycloakAuth.java_class
    end
    #  Create a OAuth2Auth provider for Keycloak
    # @overload create(vertx,config)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [Hash{String => Object}] config the json config file exported from Keycloak admin console
    # @overload create(vertx,flow,config)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [:AUTH_CODE,:CLIENT,:PASSWORD,:AUTH_JWT] flow the oauth2 flow to use
    #   @param [Hash{String => Object}] config the json config file exported from Keycloak admin console
    # @overload create(vertx,config,httpClientOptions)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [Hash{String => Object}] config the json config file exported from Keycloak admin console
    #   @param [Hash] httpClientOptions custom http client options
    # @overload create(vertx,flow,config,httpClientOptions)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [:AUTH_CODE,:CLIENT,:PASSWORD,:AUTH_JWT] flow the oauth2 flow to use
    #   @param [Hash{String => Object}] config the json config file exported from Keycloak admin console
    #   @param [Hash] httpClientOptions custom http client options
    # @return [::VertxAuthOauth2::OAuth2Auth]
    def self.create(param_1=nil,param_2=nil,param_3=nil,param_4=nil)
      if param_1.class.method_defined?(:j_del) && param_2.class == Hash && !block_given? && param_3 == nil && param_4 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::KeycloakAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(param_1.j_del,::Vertx::Util::Utils.to_json_object(param_2)),::VertxAuthOauth2::OAuth2Auth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == Symbol && param_3.class == Hash && !block_given? && param_4 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::KeycloakAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthOauth2::OAuth2FlowType.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(param_1.j_del,Java::IoVertxExtAuthOauth2::OAuth2FlowType.valueOf(param_2.to_s),::Vertx::Util::Utils.to_json_object(param_3)),::VertxAuthOauth2::OAuth2Auth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == Hash && param_3.class == Hash && !block_given? && param_4 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::KeycloakAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCoreHttp::HttpClientOptions.java_class]).call(param_1.j_del,::Vertx::Util::Utils.to_json_object(param_2),Java::IoVertxCoreHttp::HttpClientOptions.new(::Vertx::Util::Utils.to_json_object(param_3))),::VertxAuthOauth2::OAuth2Auth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == Symbol && param_3.class == Hash && param_4.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::KeycloakAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthOauth2::OAuth2FlowType.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCoreHttp::HttpClientOptions.java_class]).call(param_1.j_del,Java::IoVertxExtAuthOauth2::OAuth2FlowType.valueOf(param_2.to_s),::Vertx::Util::Utils.to_json_object(param_3),Java::IoVertxCoreHttp::HttpClientOptions.new(::Vertx::Util::Utils.to_json_object(param_4))),::VertxAuthOauth2::OAuth2Auth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{param_1},#{param_2},#{param_3},#{param_4})"
    end
  end
end
