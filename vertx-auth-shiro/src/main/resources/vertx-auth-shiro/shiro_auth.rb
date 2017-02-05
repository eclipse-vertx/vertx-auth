require 'vertx-auth-common/user'
require 'vertx/vertx'
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
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == ShiroAuth
    end
    def @@j_api_type.wrap(obj)
      ShiroAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthShiro::ShiroAuth.java_class
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
    #  Create a Shiro auth provider
    # @overload create(vertx,options)
    #   @param [::Vertx::Vertx] vertx the Vert.x instance
    #   @param [Hash] options the Shiro configuration options
    # @overload create(vertx,realmType,config)
    #   @param [::Vertx::Vertx] vertx the Vert.x instance
    #   @param [:PROPERTIES,:LDAP] realmType the Shiro realm type
    #   @param [Hash{String => Object}] config the config
    # @return [::VertxAuthShiro::ShiroAuth] the auth provider
    def self.create(param_1=nil,param_2=nil,param_3=nil)
      if param_1.class.method_defined?(:j_del) && param_2.class == Hash && !block_given? && param_3 == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthShiro::ShiroAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthShiro::ShiroAuthOptions.java_class]).call(param_1.j_del,Java::IoVertxExtAuthShiro::ShiroAuthOptions.new(::Vertx::Util::Utils.to_json_object(param_2))),::VertxAuthShiro::ShiroAuth)
      elsif param_1.class.method_defined?(:j_del) && param_2.class == Symbol && param_3.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthShiro::ShiroAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(param_1.j_del,Java::IoVertxExtAuthShiro::ShiroAuthRealmType.valueOf(param_2.to_s),::Vertx::Util::Utils.to_json_object(param_3)),::VertxAuthShiro::ShiroAuth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{param_1},#{param_2},#{param_3})"
    end
    #  Set the role prefix to distinguish from permissions when checking for isPermitted requests.
    # @param [String] rolePrefix a Prefix e.g.: "role:"
    # @return [::VertxAuthShiro::ShiroAuth] a reference to this for fluency
    def set_role_prefix(rolePrefix=nil)
      if rolePrefix.class == String && !block_given?
        return ::Vertx::Util::Utils.safe_create(@j_del.java_method(:setRolePrefix, [Java::java.lang.String.java_class]).call(rolePrefix),::VertxAuthShiro::ShiroAuth)
      end
      raise ArgumentError, "Invalid arguments when calling set_role_prefix(#{rolePrefix})"
    end
  end
end
