require 'vertx/vertx'
require 'vertx-auth-oauth2/o_auth2_auth'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.oauth2.providers.GoogleAuth
module VertxAuthOauth2
  #  Simplified factory to create an {::VertxAuthOauth2::OAuth2Auth} for Google.
  class GoogleAuth
    # @private
    # @param j_del [::VertxAuthOauth2::GoogleAuth] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthOauth2::GoogleAuth] the underlying java delegate
    def j_del
      @j_del
    end
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == GoogleAuth
    end
    def @@j_api_type.wrap(obj)
      GoogleAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthOauth2Providers::GoogleAuth.java_class
    end
    #  Create a OAuth2Auth provider for Google
    # @overload create(vertx,serviceAccountJson)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [Hash{String => Object}] serviceAccountJson the configuration json file from your Google API page
    # @overload create(vertx,clientId,clientSecret)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [String] clientId the client id given to you by Google
    #   @param [String] clientSecret the client secret given to you by Google
    # @overload create(vertx,serviceAccountJson,httpClientOptions)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [Hash{String => Object}] serviceAccountJson the configuration json file from your Google API page
    #   @param [Hash] httpClientOptions custom http client options
    # @overload create(vertx,clientId,clientSecret,httpClientOptions)
    #   @param [::Vertx::Vertx] vertx 
    #   @param [String] clientId the client id given to you by Google
    #   @param [String] clientSecret the client secret given to you by Google
    #   @param [Hash] httpClientOptions custom http client options
    # @return [::VertxAuthOauth2::OAuth2Auth]
    def self.create(param_1=nil,param_2=nil,param_3=nil,param_4=nil)
      if param_1.class.method_defined?(:j_del) && param_2.class == Hash && !block_given? && param_3 == nil && param_4 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::GoogleAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(param_1.j_del,::Vertx::Util::Utils.to_json_object(param_2)),::VertxAuthOauth2::OAuth2Auth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == String && param_3.class == String && !block_given? && param_4 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::GoogleAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class,Java::java.lang.String.java_class]).call(param_1.j_del,param_2,param_3),::VertxAuthOauth2::OAuth2Auth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == Hash && param_3.class == Hash && !block_given? && param_4 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::GoogleAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCoreHttp::HttpClientOptions.java_class]).call(param_1.j_del,::Vertx::Util::Utils.to_json_object(param_2),Java::IoVertxCoreHttp::HttpClientOptions.new(::Vertx::Util::Utils.to_json_object(param_3))),::VertxAuthOauth2::OAuth2Auth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == String && param_3.class == String && param_4.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::GoogleAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class,Java::java.lang.String.java_class,Java::IoVertxCoreHttp::HttpClientOptions.java_class]).call(param_1.j_del,param_2,param_3,Java::IoVertxCoreHttp::HttpClientOptions.new(::Vertx::Util::Utils.to_json_object(param_4))),::VertxAuthOauth2::OAuth2Auth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{param_1},#{param_2},#{param_3},#{param_4})"
    end
  end
end
