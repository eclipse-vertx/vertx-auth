require 'vertx-auth-common/user'
require 'vertx-jdbc/jdbc_client'
require 'vertx/vertx'
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
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == JDBCAuth
    end
    def @@j_api_type.wrap(obj)
      JDBCAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthJdbc::JDBCAuth.java_class
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
    #  Create a JDBC auth provider implementation
    # @param [::Vertx::Vertx] vertx 
    # @param [::VertxJdbc::JDBCClient] client the JDBC client instance
    # @return [::VertxAuthJdbc::JDBCAuth] the auth provider
    def self.create(vertx=nil,client=nil)
      if vertx.class.method_defined?(:j_del) && client.class.method_defined?(:j_del) && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthJdbc::JDBCAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::IoVertxExtJdbc::JDBCClient.java_class]).call(vertx.j_del,client.j_del),::VertxAuthJdbc::JDBCAuth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{vertx},#{client})"
    end
    #  Set the authentication query to use. Use this if you want to override the default authentication query.
    # @param [String] authenticationQuery the authentication query
    # @return [::VertxAuthJdbc::JDBCAuth] a reference to this for fluency
    def set_authentication_query(authenticationQuery=nil)
      if authenticationQuery.class == String && !block_given?
        return ::Vertx::Util::Utils.safe_create(@j_del.java_method(:setAuthenticationQuery, [Java::java.lang.String.java_class]).call(authenticationQuery),::VertxAuthJdbc::JDBCAuth)
      end
      raise ArgumentError, "Invalid arguments when calling set_authentication_query(#{authenticationQuery})"
    end
    #  Set the roles query to use. Use this if you want to override the default roles query.
    # @param [String] rolesQuery the roles query
    # @return [::VertxAuthJdbc::JDBCAuth] a reference to this for fluency
    def set_roles_query(rolesQuery=nil)
      if rolesQuery.class == String && !block_given?
        return ::Vertx::Util::Utils.safe_create(@j_del.java_method(:setRolesQuery, [Java::java.lang.String.java_class]).call(rolesQuery),::VertxAuthJdbc::JDBCAuth)
      end
      raise ArgumentError, "Invalid arguments when calling set_roles_query(#{rolesQuery})"
    end
    #  Set the permissions query to use. Use this if you want to override the default permissions query.
    # @param [String] permissionsQuery the permissions query
    # @return [::VertxAuthJdbc::JDBCAuth] a reference to this for fluency
    def set_permissions_query(permissionsQuery=nil)
      if permissionsQuery.class == String && !block_given?
        return ::Vertx::Util::Utils.safe_create(@j_del.java_method(:setPermissionsQuery, [Java::java.lang.String.java_class]).call(permissionsQuery),::VertxAuthJdbc::JDBCAuth)
      end
      raise ArgumentError, "Invalid arguments when calling set_permissions_query(#{permissionsQuery})"
    end
    #  Set the role prefix to distinguish from permissions when checking for isPermitted requests.
    # @param [String] rolePrefix a Prefix e.g.: "role:"
    # @return [::VertxAuthJdbc::JDBCAuth] a reference to this for fluency
    def set_role_prefix(rolePrefix=nil)
      if rolePrefix.class == String && !block_given?
        return ::Vertx::Util::Utils.safe_create(@j_del.java_method(:setRolePrefix, [Java::java.lang.String.java_class]).call(rolePrefix),::VertxAuthJdbc::JDBCAuth)
      end
      raise ArgumentError, "Invalid arguments when calling set_role_prefix(#{rolePrefix})"
    end
    #  Compute the hashed password given the unhashed password and the salt
    # 
    #  The implementation relays to the JDBCHashStrategy provided.
    # @param [String] password the unhashed password
    # @param [String] salt the salt
    # @return [String] the hashed password
    def compute_hash(password=nil,salt=nil)
      if password.class == String && salt.class == String && !block_given?
        return @j_del.java_method(:computeHash, [Java::java.lang.String.java_class,Java::java.lang.String.java_class]).call(password,salt)
      end
      raise ArgumentError, "Invalid arguments when calling compute_hash(#{password},#{salt})"
    end
    #  Compute a salt string.
    # 
    #  The implementation relays to the JDBCHashStrategy provided.
    # @return [String] a non null salt value
    def generate_salt
      if !block_given?
        return @j_del.java_method(:generateSalt, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling generate_salt()"
    end
  end
end
