require 'vertx-auth-common/user'
require 'vertx/vertx'
require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.htdigest.HtdigestAuth
module VertxAuthHtdigest
  #  An extension of AuthProvider which is using .htdigest file as store
  class HtdigestAuth < ::VertxAuthCommon::AuthProvider
    # @private
    # @param j_del [::VertxAuthHtdigest::HtdigestAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthHtdigest::HtdigestAuth] the underlying java delegate
    def j_del
      @j_del
    end
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == HtdigestAuth
    end
    def @@j_api_type.wrap(obj)
      HtdigestAuth.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthHtdigest::HtdigestAuth.java_class
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
    #  Creates an instance of HtdigestAuth by using the given htfile file.
    # @param [::Vertx::Vertx] vertx 
    # @param [String] htfile the existing htfile.
    # @return [::VertxAuthHtdigest::HtdigestAuth] the created instance of {::VertxAuthHtdigest::HtdigestAuth}s
    def self.create(vertx=nil,htfile=nil)
      if vertx.class.method_defined?(:j_del) && !block_given? && htfile == nil
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthHtdigest::HtdigestAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class]).call(vertx.j_del),::VertxAuthHtdigest::HtdigestAuth)
      elsif vertx.class.method_defined?(:j_del) && htfile.class == String && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthHtdigest::HtdigestAuth.java_method(:create, [Java::IoVertxCore::Vertx.java_class,Java::java.lang.String.java_class]).call(vertx.j_del,htfile),::VertxAuthHtdigest::HtdigestAuth)
      end
      raise ArgumentError, "Invalid arguments when calling create(#{vertx},#{htfile})"
    end
    #  Return the currently used realm
    # @return [String] the realm
    def realm
      if !block_given?
        return @j_del.java_method(:realm, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling realm()"
    end
  end
end
