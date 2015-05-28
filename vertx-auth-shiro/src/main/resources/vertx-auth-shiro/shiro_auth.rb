require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.shiro.ShiroAuth
module VertxAuthShiro
  #  Factory interface for creating Apache Shiro based {::VertxAuthCommon::AuthProvider} instances.
  class ShiroAuth < ::VertxAuthCommon::AuthProvider
    # @private
    # @param j_del [::VertxAuthShiro::ShiroAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthShiro::ShiroAuth] the underlying java delegate
    def j_del
      @j_del
    end
    #  Create a Shiro auth provider
    # @param [::Vertx::Vertx] vertx the Vert.x instance
    # @param [:PROPERTIES,:LDAP] realmType the Shiro realm type
    # @param [Hash{String => Object}] config the config
    # @return [::VertxAuthShiro::ShiroAuth] the auth provider
    def self.create(vertx=nil,realmType=nil,config=nil)
      if vertx.class.method_defined?(:j_del) && realmType.class == Symbol && config.class == Hash && !block_given?
        return ::VertxAuthShiro::ShiroAuth.new(Java::IoVertxExtAuthShiro::ShiroAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(vertx.j_del,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.valueOf(realmType),::Vertx::Util::Utils.to_json_object(config)))
      end
      raise ArgumentError, "Invalid arguments when calling create(vertx,realmType,config)"
    end
    #  Set the role prefix to distinguish from permissions when checking for isPermitted requests.
    # @param [String] rolePrefix a Prefix e.g.: "role:"
    # @return [::VertxAuthShiro::ShiroAuth] a reference to this for fluency
    def set_role_prefix(rolePrefix=nil)
      if rolePrefix.class == String && !block_given?
        return ::VertxAuthShiro::ShiroAuth.new(@j_del.java_method(:setRolePrefix, [Java::java.lang.String.java_class]).call(rolePrefix))
      end
      raise ArgumentError, "Invalid arguments when calling set_role_prefix(rolePrefix)"
    end
  end
end
