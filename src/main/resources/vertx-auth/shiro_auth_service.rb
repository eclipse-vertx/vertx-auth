require 'vertx-auth/auth_service'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.shiro.ShiroAuthService
module VertxAuth
  #  An Auth service implementation that uses Apache Shiro internally.
  #  <p>
  class ShiroAuthService < ::VertxAuth::AuthService
    # @private
    # @param j_del [::VertxAuth::ShiroAuthService] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::ShiroAuthService] the underlying java delegate
    def j_del
      @j_del
    end
    #  Create an auth service using the specified auth realm type.
    # @param [::Vertx::Vertx] vertx the Vert.x intance
    # @param [:PROPERTIES,:LDAP] authRealmType the auth realm type
    # @param [Hash{String => Object}] config the config to pass to the provider
    # @return [::VertxAuth::AuthService] the auth service
    def self.create(vertx=nil,authRealmType=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && authRealmType.class == Symbol && config.class == Hash && !block_given?
        return ::VertxAuth::AuthService.new(Java::IoVertxExtAuthShiro::ShiroAuthService.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(vertx.j_del,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.valueOf(authRealmType),::Vertx::Util::Utils.to_json_object(config)))
      end
      raise ArgumentError, "Invalid arguments when calling create(vertx,authRealmType,config)"
    end
  end
end
