require 'vertx-auth-common/user'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.mongo.HashStrategy
module VertxAuthMongo
  #  Determines how the hashing is computed in the implementation You can implement this to provide a different hashing
  #  strategy to the default.
  class HashStrategy
    # @private
    # @param j_del [::VertxAuthMongo::HashStrategy] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthMongo::HashStrategy] the underlying java delegate
    def j_del
      @j_del
    end
    @@j_api_type = Object.new
    def @@j_api_type.accept?(obj)
      obj.class == HashStrategy
    end
    def @@j_api_type.wrap(obj)
      HashStrategy.new(obj)
    end
    def @@j_api_type.unwrap(obj)
      obj.j_del
    end
    def self.j_api_type
      @@j_api_type
    end
    def self.j_class
      Java::IoVertxExtAuthMongo::HashStrategy.java_class
    end
    #  Compute the hashed password given the unhashed password and the user
    # @param [String] password the unhashed password
    # @param [::VertxAuthCommon::User] user the user to get the salt for. This paramter is needed, if the  is declared to be used
    # @return [String] the hashed password
    def compute_hash(password=nil,user=nil)
      if password.class == String && user.class.method_defined?(:j_del) && !block_given?
        return @j_del.java_method(:computeHash, [Java::java.lang.String.java_class,Java::IoVertxExtAuth::User.java_class]).call(password,user.j_del)
      end
      raise ArgumentError, "Invalid arguments when calling compute_hash(#{password},#{user})"
    end
    #  Retrieve the password from the user, or as clear text or as hashed version, depending on the definition
    # @param [::VertxAuthCommon::User] user the user to get the stored password for
    # @return [String] the password, either as hashed version or as cleartext, depending on the preferences
    def get_stored_pwd(user=nil)
      if user.class.method_defined?(:j_del) && !block_given?
        return @j_del.java_method(:getStoredPwd, [Java::IoVertxExtAuth::User.java_class]).call(user.j_del)
      end
      raise ArgumentError, "Invalid arguments when calling get_stored_pwd(#{user})"
    end
    #  Retrieve the salt. The source of the salt can be the external salt or the propriate column of the given user,
    #  depending on the defined HashSaltStyle
    # @param [::VertxAuthCommon::User] user the user to get the salt for. This paramter is needed, if the  is declared to be used
    # @return [String] null in case of  the salt of the user or a defined external salt
    def get_salt(user=nil)
      if user.class.method_defined?(:j_del) && !block_given?
        return @j_del.java_method(:getSalt, [Java::IoVertxExtAuth::User.java_class]).call(user.j_del)
      end
      raise ArgumentError, "Invalid arguments when calling get_salt(#{user})"
    end
    #  Set an external salt. This method should be used in case of 
    # @param [String] salt the salt, which shall be used
    # @return [void]
    def set_external_salt(salt=nil)
      if salt.class == String && !block_given?
        return @j_del.java_method(:setExternalSalt, [Java::java.lang.String.java_class]).call(salt)
      end
      raise ArgumentError, "Invalid arguments when calling set_external_salt(#{salt})"
    end
    #  Set the saltstyle as defined by HashSaltStyle.
    # @param [:NO_SALT,:COLUMN,:EXTERNAL] saltStyle the HashSaltStyle to be used
    # @return [void]
    def set_salt_style(saltStyle=nil)
      if saltStyle.class == Symbol && !block_given?
        return @j_del.java_method(:setSaltStyle, [Java::IoVertxExtAuthMongo::HashSaltStyle.java_class]).call(Java::IoVertxExtAuthMongo::HashSaltStyle.valueOf(saltStyle.to_s))
      end
      raise ArgumentError, "Invalid arguments when calling set_salt_style(#{saltStyle})"
    end
    #  Get the defined HashSaltStyle of the current instance
    # @return [:NO_SALT,:COLUMN,:EXTERNAL] the saltStyle
    def get_salt_style
      if !block_given?
        return @j_del.java_method(:getSaltStyle, []).call().name.intern
      end
      raise ArgumentError, "Invalid arguments when calling get_salt_style()"
    end
  end
end
