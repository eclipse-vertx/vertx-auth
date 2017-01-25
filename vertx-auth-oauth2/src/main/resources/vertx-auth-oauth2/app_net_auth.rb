require 'vertx/vertx'
require 'vertx-auth-oauth2/o_auth2_auth'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.oauth2.providers.AppNetAuth
module VertxAuthOauth2
  #  Simplified factory to create an  for App.net.
  class AppNetAuth
    # @private
    # @param j_del [::VertxAuthOauth2::AppNetAuth] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthOauth2::AppNetAuth] the underlying java delegate
    def j_del
      @j_del
    end
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == AppNetAuth
    end
    def @@j_api_type.wrap(obj)
      AppNetAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthOauth2Providers::AppNetAuth.java_class
    end
    #  Create a OAuth2Auth provider for App.net
    # @param [::Vertx::Vertx] vertx 
    # @param [String] clientId the client id given to you by App.net
    # @param [String] clientSecret the client secret given to you by App.net
    # @param [Hash] httpClientOptions custom http client options
    # @return [::VertxAuthOauth2::OAuth2Auth]
    def self.create(vertx=nil,clientId=nil,clientSecret=nil,httpClientOptions=nil)
      if vertx.class.method_defined?(:j_del) && clientId.class == String && clientSecret.class == String && !block_given? && httpClientOptions == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::AppNetAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class,Java::java.lang.String.java_class]).call(vertx.j_del,clientId,clientSecret),::VertxAuthOauth2::OAuth2Auth)
      elsif vertx.class.method_defined?(:j_del) && clientId.class == String && clientSecret.class == String && httpClientOptions.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2Providers::AppNetAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class,Java::java.lang.String.java_class,Java::IoVertxCoreHttp::HttpClientOptions.java_class]).call(vertx.j_del,clientId,clientSecret,Java::IoVertxCoreHttp::HttpClientOptions.new(::Vertx::Util::Utils.to_json_object(httpClientOptions))),::VertxAuthOauth2::OAuth2Auth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{vertx},#{clientId},#{clientSecret},#{httpClientOptions})"
    end
  end
end
