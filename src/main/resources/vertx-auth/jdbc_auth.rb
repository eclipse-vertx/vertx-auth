require 'vertx-jdbc/jdbc_client'
require 'vertx-auth/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.jdbc.JDBCAuth
module VertxAuth
  #  Factory interface for creating {::VertxAuth::AuthProvider} instances that use the Vert.x JDBC client
  class JDBCAuth < ::VertxAuth::AuthProvider
    # @private
    # @param j_del [::VertxAuth::JDBCAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::JDBCAuth] the underlying java delegate
    def j_del
      @j_del
    end
    #  Create a JDBC auth provider implementation
    # @param [::VertxJdbc::JDBCClient] client the JDBC client instance
    # @return [::VertxAuth::JDBCAuth] the auth provider
    def self.create(client=nil)
      if client.class.method_defined?(:j_del) && !block_given?
        return ::VertxAuth::JDBCAuth.new(Java::IoVertxExtAuthJdbc::JDBCAuth.java_method(:create, [Java::IoVertxExtJdbc::JDBCClient.java_class]).call(client.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling create(client)"
    end
    #  Set the authentication query to use. Use this if you want to override the default authentication query.
    # @param [String] authenticationQuery the authentication query
    # @return [::VertxAuth::JDBCAuth] a reference to this for fluency
    def set_authentication_query(authenticationQuery=nil)
      if authenticationQuery.class == String && !block_given?
        return ::VertxAuth::JDBCAuth.new(@j_del.java_method(:setAuthenticationQuery, [Java::java.lang.String.java_class]).call(authenticationQuery))
      end
      raise ArgumentError, "Invalid arguments when calling set_authentication_query(authenticationQuery)"
    end
    #  Set the roles query to use. Use this if you want to override the default roles query.
    # @param [String] rolesQuery the roles query
    # @return [::VertxAuth::JDBCAuth] a reference to this for fluency
    def set_roles_query(rolesQuery=nil)
      if rolesQuery.class == String && !block_given?
        return ::VertxAuth::JDBCAuth.new(@j_del.java_method(:setRolesQuery, [Java::java.lang.String.java_class]).call(rolesQuery))
      end
      raise ArgumentError, "Invalid arguments when calling set_roles_query(rolesQuery)"
    end
    #  Set the permissions query to use. Use this if you want to override the default permissions query.
    # @param [String] permissionsQuery the permissions query
    # @return [::VertxAuth::JDBCAuth] a reference to this for fluency
    def set_permissions_query(permissionsQuery=nil)
      if permissionsQuery.class == String && !block_given?
        return ::VertxAuth::JDBCAuth.new(@j_del.java_method(:setPermissionsQuery, [Java::java.lang.String.java_class]).call(permissionsQuery))
      end
      raise ArgumentError, "Invalid arguments when calling set_permissions_query(permissionsQuery)"
    end
  end
end
