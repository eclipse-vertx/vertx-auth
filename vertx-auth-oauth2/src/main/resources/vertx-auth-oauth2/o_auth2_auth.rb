require 'vertx/vertx'
require 'vertx-auth-oauth2/access_token'
require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.oauth2.OAuth2Auth
module VertxAuthOauth2
  #  Factory interface for creating OAuth2 based {::VertxAuthCommon::AuthProvider} instances.
  class OAuth2Auth < ::VertxAuthCommon::AuthProvider
    # @private
    # @param j_del [::VertxAuthOauth2::OAuth2Auth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthOauth2::OAuth2Auth] the underlying java delegate
    def j_del
      @j_del
    end
    #  Create a OAuth2 auth provider
    # @param [::Vertx::Vertx] vertx the Vertx instance
    # @param [:AUTH_CODE,:CLIENT,:PASSWORD] flow 
    # @param [Hash{String => Object}] config the config
    # @return [::VertxAuthOauth2::OAuth2Auth] the auth provider
    def self.create(vertx=nil,flow=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && flow.class == Symbol && !block_given? && config == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2::OAuth2Auth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthOauth2::OAuth2FlowType.java_class]).call(vertx.j_del,Java::IoVertxExtAuthOauth2::OAuth2FlowType.valueOf(flow)),::VertxAuthOauth2::OAuth2Auth)
      elsif vertx.class.method_defined?(:j_del) && flow.class == Symbol && config.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthOauth2::OAuth2Auth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthOauth2::OAuth2FlowType.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(vertx.j_del,Java::IoVertxExtAuthOauth2::OAuth2FlowType.valueOf(flow),::Vertx::Util::Utils.to_json_object(config)),::VertxAuthOauth2::OAuth2Auth)
      end
      raise ArgumentError, "Invalid arguments when calling create(vertx,flow,config)"
    end
    #  Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
    # @param [Hash{String => Object}] params 
    # @return [String]
    def authorize_url(params=nil)
      if params.class == Hash && !block_given?
        return @j_del.java_method(:authorizeURL, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(params))
      end
      raise ArgumentError, "Invalid arguments when calling authorize_url(params)"
    end
    #  Returns the Access Token object.
    # @param [Hash{String => Object}] params - JSON with the options, each flow requires different options.
    # @yield - The handler returning the results.
    # @return [void]
    def get_token(params=nil)
      if params.class == Hash && block_given?
        return @j_del.java_method(:getToken, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(params),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ::Vertx::Util::Utils.safe_create(ar.result,::VertxAuthOauth2::AccessToken) : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling get_token(params)"
    end
    #  Call OAuth2 APIs.
    # @param [:OPTIONS,:GET,:HEAD,:POST,:PUT,:DELETE,:TRACE,:CONNECT,:PATCH] method HttpMethod
    # @param [String] path target path
    # @param [Hash{String => Object}] params parameters
    # @yield handler
    # @return [self]
    def api(method=nil,path=nil,params=nil)
      if method.class == Symbol && path.class == String && params.class == Hash && block_given?
        @j_del.java_method(:api, [Java::IoVertxCoreHttp::HttpMethod.java_class,Java::java.lang.String.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(Java::IoVertxCoreHttp::HttpMethod.valueOf(method),path,::Vertx::Util::Utils.to_json_object(params),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result != nil ? JSON.parse(ar.result.encode) : nil : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling api(method,path,params)"
    end
  end
end
