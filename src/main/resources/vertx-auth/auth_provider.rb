require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.AuthProvider
module VertxAuth
  #  This interface is implemented by auth providers which provide the actual auth functionality -
  #  e.g. we have a implementation which uses Apache Shiro.
  #  <p>
  #  If you wish to use the auth service with other providers, implement this interface for your provider.
  class AuthProvider
    # @private
    # @param j_del [::VertxAuth::AuthProvider] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::AuthProvider] the underlying java delegate
    def j_del
      @j_del
    end
    #  Handle the actual login
    # @param [Hash{String => Object}] principal represents the unique id (e.g. username) of the user being logged in
    # @param [Hash{String => Object}] credentials the credentials - this can contain anything your provider expects, e.g. password
    # @yield - this must return a failed result if login fails and it must return a succeeded result if the login succeeds
    # @return [void]
    def login(principal=nil,credentials=nil)
      if principal.class == Hash && credentials.class == Hash && block_given?
        return @j_del.java_method(:login, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),::Vertx::Util::Utils.to_json_object(credentials),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling login(principal,credentials)"
    end
    #  Handle whether a principal has a role
    # @param [Hash{String => Object}] principal represents the unique id (e.g. username) of the user being logged in
    # @param [String] role the role
    # @yield this must return a failure if the check could not be performed - e.g. the principal is not known. Otherwise it must return a succeeded result which contains a boolean `true` if the principal has the role, or `false` if they do not have the role.
    # @return [void]
    def has_role(principal=nil,role=nil)
      if principal.class == Hash && role.class == String && block_given?
        return @j_del.java_method(:hasRole, [Java::IoVertxCoreJson::JsonObject.java_class,Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),role,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling has_role(principal,role)"
    end
    #  Handle whether a principal has a permission
    # @param [Hash{String => Object}] principal represents the unique id (e.g. username) of the user being logged in
    # @param [String] permission the permission
    # @yield this must return a failure if the check could not be performed - e.g. the principal is not known. Otherwise it must return a succeeded result which contains a boolean `true` if the principal has the permission, or `false` if they do not have the permission.
    # @return [void]
    def has_permission(principal=nil,permission=nil)
      if principal.class == Hash && permission.class == String && block_given?
        return @j_del.java_method(:hasPermission, [Java::IoVertxCoreJson::JsonObject.java_class,Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),permission,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling has_permission(principal,permission)"
    end
  end
end
