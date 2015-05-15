require 'vertx-auth/user'
require 'vertx/buffer'
require 'vertx-auth/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.ClusterableAuthProvider
module VertxAuth
  class ClusterableAuthProvider < ::VertxAuth::AuthProvider
    # @private
    # @param j_del [::VertxAuth::ClusterableAuthProvider] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuth::ClusterableAuthProvider] the underlying java delegate
    def j_del
      @j_del
    end
    # @param [::VertxAuth::User] user
    # @return [::Vertx::Buffer]
    def to_buffer(user=nil)
      if user.class.method_defined?(:j_del) && !block_given?
        return ::Vertx::Buffer.new(@j_del.java_method(:toBuffer, [Java::IoVertxExtAuth::User.java_class]).call(user.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling to_buffer(user)"
    end
    # @param [::Vertx::Buffer] buffer
    # @return [::VertxAuth::User]
    def from_buffer(buffer=nil)
      if buffer.class.method_defined?(:j_del) && !block_given?
        return ::VertxAuth::User.new(@j_del.java_method(:fromBuffer, [Java::IoVertxCoreBuffer::Buffer.java_class]).call(buffer.j_del))
      end
      raise ArgumentError, "Invalid arguments when calling from_buffer(buffer)"
    end
  end
end
