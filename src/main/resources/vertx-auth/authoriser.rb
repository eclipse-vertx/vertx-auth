require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.Authoriser
module VertxAuth
  class Authoriser
    # @private
    # @param j_del [::VertxAuth::Authoriser] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::Authoriser] the underlying java delegate
    def j_del
      @j_del
    end
    # @param [Hash{String => Object}] principal
    # @param [String] role
    # @yield 
    # @return [void]
    def has_role(principal=nil,role=nil)
      if principal.class == Hash && role.class == String && block_given?
        return @j_del.java_method(:hasRole, [Java::IoVertxCoreJson::JsonObject.java_class,Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),role,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling has_role(principal,role)"
    end
    # @param [Hash{String => Object}] principal
    # @param [String] permission
    # @yield 
    # @return [void]
    def has_permission(principal=nil,permission=nil)
      if principal.class == Hash && permission.class == String && block_given?
        return @j_del.java_method(:hasPermission, [Java::IoVertxCoreJson::JsonObject.java_class,Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),permission,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling has_permission(principal,permission)"
    end
    # @param [Hash{String => Object}] principal
    # @param [Set<String>] roles
    # @yield 
    # @return [void]
    def has_roles(principal=nil,roles=nil)
      if principal.class == Hash && roles.class == Set && block_given?
        return @j_del.java_method(:hasRoles, [Java::IoVertxCoreJson::JsonObject.java_class,Java::JavaUtil::Set.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),Java::JavaUtil::LinkedHashSet.new(roles.map { |element| element }),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling has_roles(principal,roles)"
    end
    # @param [Hash{String => Object}] principal
    # @param [Set<String>] permissions
    # @yield 
    # @return [void]
    def has_permissions(principal=nil,permissions=nil)
      if principal.class == Hash && permissions.class == Set && block_given?
        return @j_del.java_method(:hasPermissions, [Java::IoVertxCoreJson::JsonObject.java_class,Java::JavaUtil::Set.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),Java::JavaUtil::LinkedHashSet.new(permissions.map { |element| element }),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling has_permissions(principal,permissions)"
    end
  end
end
