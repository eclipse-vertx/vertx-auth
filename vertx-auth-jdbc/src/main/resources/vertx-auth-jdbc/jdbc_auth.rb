require 'vertx-jdbc/jdbc_client'
require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.jdbc.JDBCAuth
module VertxAuthJdbc
  #  Factory interface for creating {::VertxAuthCommon::AuthProvider} instances that use the Vert.x JDBC client
  class JDBCAuth < ::VertxAuthCommon::AuthProvider
    # @private
    # @param j_del [::VertxAuthJdbc::JDBCAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthJdbc::JDBCAuth] the underlying java delegate
    def j_del
      @j_del
    end
    #  Create a JDBC auth provider implementation
    # @param [::VertxJdbc::JDBCClient] client the JDBC client instance
    # @return [::VertxAuthJdbc::JDBCAuth] the auth provider
    def self.create(client=nil)
      if client.class.method_defined?(:j_del) && !block_given?
        return ::VertxAuthJdbc::JDBCAuth.new(Java::IoVertxExtAuthJdbc::JDBCAuth.java_method(:create, [Java::IoVertxExtJdbc::JDBCClient.java_class]).call(client.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling create(client)"
    end
    #  Set the authentication query to use. Use this if you want to override the default authentication query.
    # @param [String] authenticationQuery the authentication query
    # @return [::VertxAuthJdbc::JDBCAuth] a reference to this for fluency
    def set_authentication_query(authenticationQuery=nil)
      if authenticationQuery.class == String && !block_given?
        return ::VertxAuthJdbc::JDBCAuth.new(@j_del.java_method(:setAuthenticationQuery, [Java::java.lang.String.java_class]).call(authenticationQuery))
      end
      raise ArgumentError, "Invalid arguments when calling set_authentication_query(authenticationQuery)"
    end
    #  Set the permissions query to use. Use this if you want to override the default permissions query.
    # @param [String] permissionsQuery the permissions query
    # @return [::VertxAuthJdbc::JDBCAuth] a reference to this for fluency
    def set_permissions_query(permissionsQuery=nil)
      if permissionsQuery.class == String && !block_given?
        return ::VertxAuthJdbc::JDBCAuth.new(@j_del.java_method(:setPermissionsQuery, [Java::java.lang.String.java_class]).call(permissionsQuery))
      end
      raise ArgumentError, "Invalid arguments when calling set_permissions_query(permissionsQuery)"
    end
  end
end
