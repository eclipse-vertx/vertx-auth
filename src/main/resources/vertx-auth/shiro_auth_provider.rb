require 'vertx-auth/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.shiro.ShiroAuthProvider
module VertxAuth
  #  @author <a href="http://tfox.org">Tim Fox</a>
  class ShiroAuthProvider < ::VertxAuth::AuthProvider
    # @private
    # @param j_del [::VertxAuth::ShiroAuthProvider] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::ShiroAuthProvider] the underlying java delegate
    def j_del
      @j_del
    end
    # @param [::Vertx::Vertx] vertx
    # @param [:PROPERTIES,:LDAP] shiroAuthRealmType
    # @param [Hash{String => Object}] config
    # @return [::VertxAuth::ShiroAuthProvider]
    def self.create(vertx=nil,shiroAuthRealmType=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && shiroAuthRealmType.class == Symbol && config.class == Hash && !block_given?
        return ::VertxAuth::ShiroAuthProvider.new(Java::IoVertxExtAuthShiro::ShiroAuthProvider.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(vertx.j_del,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.valueOf(shiroAuthRealmType),::Vertx::Util::Utils.to_json_object(config)))
      end
      raise ArgumentError, "Invalid arguments when calling create(vertx,shiroAuthRealmType,config)"
    end
  end
end
