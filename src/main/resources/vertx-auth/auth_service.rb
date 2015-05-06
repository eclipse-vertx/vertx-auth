require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.AuthService
module VertxAuth
  #  Vert.x authentication and authorisation service.
  #  <p>
  #  Handles authentication and role/permission based authorisation.
  class AuthService
    # @private
    # @param j_del [::VertxAuth::AuthService] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::AuthService] the underlying java delegate
    def j_del
      @j_del
    end
    #  Create an auth service instance using the specified auth provider class name.
    # @param [::Vertx::Vertx] vertx the Vert.x instance
    # @param [String] className the fully qualified class name of the auth provider implementation class
    # @return [::VertxAuth::AuthService] the auth service
    def self.create_from_class_name(vertx=nil,className=nil)
      if vertx.class.method_defined?(:j_del) && className.class == String && !block_given?
        return ::VertxAuth::AuthService.new(Java::IoVertxExtAuth::AuthService.java_method(:createFromClassName, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class]).call(vertx.j_del,className))
      end
      raise ArgumentError, "Invalid arguments when calling create_from_class_name(vertx,className)"
    end
    #  Create a proxy to an auth service that is deployed somwehere on the event bus.
    # @param [::Vertx::Vertx] vertx the vert.x instance
    # @param [String] address the address on the event bus where the auth service is listening
    # @return [::VertxAuth::AuthService] the proxy
    def self.create_event_bus_proxy(vertx=nil,address=nil)
      if vertx.class.method_defined?(:j_del) && address.class == String && !block_given?
        return ::VertxAuth::AuthService.new(Java::IoVertxExtAuth::AuthService.java_method(:createEventBusProxy, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class]).call(vertx.j_del,address))
      end
      raise ArgumentError, "Invalid arguments when calling create_event_bus_proxy(vertx,address)"
    end
    #  Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
    #  provider is expecting. The default login ID timeout will be used.
    # @param [Hash{String => Object}] principal represents the unique id (e.g. username) of the user being logged in
    # @param [Hash{String => Object}] credentials the credentials - e.g. password
    # @yield will be passed a failed result if login failed or will be passed a succeeded result containing the login ID (a string) if login was successful.
    # @return [self]
    def login(principal=nil,credentials=nil)
      if principal.class == Hash && credentials.class == Hash && block_given?
        @j_del.java_method(:login, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),::Vertx::Util::Utils.to_json_object(credentials),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling login(principal,credentials)"
    end
    #  Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
    #  provider is expecting. The specified login ID timeout will be used.
    # @param [Hash{String => Object}] principal represents the unique id (e.g. username) of the user being logged in
    # @param [Hash{String => Object}] credentials the credentials
    # @param [Fixnum] timeout the login timeout to use, in ms
    # @yield will be passed a failed result if login failed or will be passed a succeeded result containing the login ID (a string) if login was successful.
    # @return [self]
    def login_with_timeout(principal=nil,credentials=nil,timeout=nil)
      if principal.class == Hash && credentials.class == Hash && timeout.class == Fixnum && block_given?
        @j_del.java_method(:loginWithTimeout, [Java::IoVertxCoreJson::JsonObject.java_class,Java::IoVertxCoreJson::JsonObject.java_class,Java::long.java_class,Java::IoVertxCore::Handler.java_class]).call(::Vertx::Util::Utils.to_json_object(principal),::Vertx::Util::Utils.to_json_object(credentials),timeout,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling login_with_timeout(principal,credentials,timeout)"
    end
    #  Logout the user
    # @param [String] loginID the login ID as provided by {@link #login}.
    # @yield will be called with success or failure
    # @return [self]
    def logout(loginID=nil)
      if loginID.class == String && block_given?
        @j_del.java_method(:logout, [Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(loginID,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling logout(loginID)"
    end
    #  Refresh an existing login ID so it doesn't expire
    # @param [String] loginID the login ID as provided by {@link #login}.
    # @yield will be called with success or failure
    # @return [self]
    def refresh_login_session(loginID=nil)
      if loginID.class == String && block_given?
        @j_del.java_method(:refreshLoginSession, [Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(loginID,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling refresh_login_session(loginID)"
    end
    #  Does the user have the specified role?
    # @param [String] loginID the login ID as provided by {@link #login}.
    # @param [String] role the role
    # @yield will be called with the result - true if has role, false if not
    # @return [self]
    def has_role(loginID=nil,role=nil)
      if loginID.class == String && role.class == String && block_given?
        @j_del.java_method(:hasRole, [Java::java.lang.String.java_class,Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(loginID,role,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling has_role(loginID,role)"
    end
    #  Does the user have the specified roles?
    # @param [String] loginID the login ID as provided by {@link #login}.
    # @param [Set<String>] roles the set of roles
    # @yield will be called with the result - true if has roles, false if not
    # @return [self]
    def has_roles(loginID=nil,roles=nil)
      if loginID.class == String && roles.class == Set && block_given?
        @j_del.java_method(:hasRoles, [Java::java.lang.String.java_class,Java::JavaUtil::Set.java_class,Java::IoVertxCore::Handler.java_class]).call(loginID,Java::JavaUtil::LinkedHashSet.new(roles.map { |element| element }),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling has_roles(loginID,roles)"
    end
    #  Does the user have the specified permission?
    # @param [String] loginID the login ID as provided by {@link #login}.
    # @param [String] permission the permission
    # @yield will be called with the result - true if has permission, false if not
    # @return [self]
    def has_permission(loginID=nil,permission=nil)
      if loginID.class == String && permission.class == String && block_given?
        @j_del.java_method(:hasPermission, [Java::java.lang.String.java_class,Java::java.lang.String.java_class,Java::IoVertxCore::Handler.java_class]).call(loginID,permission,(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling has_permission(loginID,permission)"
    end
    #  Does the user have the specified permissions?
    # @param [String] loginID the login ID as provided by {@link #login}.
    # @param [Set<String>] permissions the set of permissions
    # @yield will be called with the result - true if has permissions, false if not
    # @return [self]
    def has_permissions(loginID=nil,permissions=nil)
      if loginID.class == String && permissions.class == Set && block_given?
        @j_del.java_method(:hasPermissions, [Java::java.lang.String.java_class,Java::JavaUtil::Set.java_class,Java::IoVertxCore::Handler.java_class]).call(loginID,Java::JavaUtil::LinkedHashSet.new(permissions.map { |element| element }),(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
        return self
      end
      raise ArgumentError, "Invalid arguments when calling has_permissions(loginID,permissions)"
    end
    #  Set the reaper period - how often to check for expired logins, in ms.
    # @param [Fixnum] reaperPeriod the reaper period, in ms
    # @return [self]
    def set_reaper_period(reaperPeriod=nil)
      if reaperPeriod.class == Fixnum && !block_given?
        @j_del.java_method(:setReaperPeriod, [Java::long.java_class]).call(reaperPeriod)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_reaper_period(reaperPeriod)"
    end
    #  Start the service
    # @return [void]
    def start
      if !block_given?
        return @j_del.java_method(:start, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling start()"
    end
    #  Stop the service
    # @return [void]
    def stop
      if !block_given?
        return @j_del.java_method(:stop, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling stop()"
    end
  end
end
