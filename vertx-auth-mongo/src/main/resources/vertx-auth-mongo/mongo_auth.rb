require 'vertx-mongo/mongo_client'
require 'vertx-auth-mongo/hash_strategy'
require 'vertx-auth-common/auth_provider'
require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.mongo.MongoAuth
module VertxAuthMongo
  #  An extension of AuthProvider which is using  as store
  class MongoAuth < ::VertxAuthCommon::AuthProvider
    # @private
    # @param j_del [::VertxAuthMongo::MongoAuth] the java delegate
    def initialize(j_del)
      super(j_del)
      @j_del = j_del
    end
    # @private
    # @return [::VertxAuthMongo::MongoAuth] the underlying java delegate
    def j_del
      @j_del
    end
    #  Creates an instance of MongoAuth by using the given  and configuration object. An example for a
    #  configuration object:
    #  
    #  <pre>
    #  JsonObject js = new JsonObject();
    #  js.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
    #  </pre>
    # @param [::VertxMongo::MongoClient] mongoClient an instance of  to be used for data storage and retrival
    # @param [Hash{String => Object}] config the configuration object for the current instance. By this
    # @return [::VertxAuthMongo::MongoAuth] the created instance of {::VertxAuthMongo::MongoAuth}s
    def self.create(mongoClient=nil,config=nil)
      if mongoClient.class.method_defined?(:j_del) && config.class == Hash && !block_given?
        return ::Vertx::Util::Utils.safe_create(Java::IoVertxExtAuthMongo::MongoAuth.java_method(:create, [Java::IoVertxExtMongo::MongoClient.java_class,Java::IoVertxCoreJson::JsonObject.java_class]).call(mongoClient.j_del,::Vertx::Util::Utils.to_json_object(config)),::VertxAuthMongo::MongoAuth)
      end
      raise ArgumentError, "Invalid arguments when calling create(mongoClient,config)"
    end
    #  Set the name of the collection to be used. Defaults to DEFAULT_COLLECTION_NAME
    # @param [String] collectionName the name of the collection to be used for storing and reading user data
    # @return [self]
    def set_collection_name(collectionName=nil)
      if collectionName.class == String && !block_given?
        @j_del.java_method(:setCollectionName, [Java::java.lang.String.java_class]).call(collectionName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_collection_name(collectionName)"
    end
    #  Set the name of the field to be used for the username. Defaults to DEFAULT_USERNAME_FIELD
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_username_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setUsernameField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_username_field(fieldName)"
    end
    #  Set the name of the field to be used for the password Defaults to DEFAULT_PASSWORD_FIELD
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_password_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setPasswordField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_password_field(fieldName)"
    end
    #  Set the name of the field to be used for the roles. Defaults to DEFAULT_ROLE_FIELD. Roles are expected to
    #  be saved as JsonArray
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_role_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setRoleField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_role_field(fieldName)"
    end
    #  Set the name of the field to be used for the permissions. Defaults to DEFAULT_PERMISSION_FIELD.
    #  Permissions are expected to be saved as JsonArray
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_permission_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setPermissionField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_permission_field(fieldName)"
    end
    #  Set the name of the field to be used as property for the username in the method
    #  {::VertxAuthCommon::AuthProvider#authenticate}. Defaults to DEFAULT_CREDENTIAL_USERNAME_FIELD
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_username_credential_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setUsernameCredentialField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_username_credential_field(fieldName)"
    end
    #  Set the name of the field to be used as property for the password of credentials in the method
    #  {::VertxAuthCommon::AuthProvider#authenticate}. Defaults to DEFAULT_CREDENTIAL_PASSWORD_FIELD
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_password_credential_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setPasswordCredentialField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_password_credential_field(fieldName)"
    end
    #  Set the name of the field to be used for the salt. Only used when {::VertxAuthMongo::HashStrategy#set_salt_style} is
    #  set to 
    # @param [String] fieldName the name of the field to be used
    # @return [self]
    def set_salt_field(fieldName=nil)
      if fieldName.class == String && !block_given?
        @j_del.java_method(:setSaltField, [Java::java.lang.String.java_class]).call(fieldName)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_salt_field(fieldName)"
    end
    #  The name of the collection used to store User objects inside. Defaults to DEFAULT_COLLECTION_NAME
    # @return [String] the collectionName
    def get_collection_name
      if !block_given?
        return @j_del.java_method(:getCollectionName, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_collection_name()"
    end
    #  Get the name of the field to be used for the username. Defaults to DEFAULT_USERNAME_FIELD
    # @return [String] the usernameField
    def get_username_field
      if !block_given?
        return @j_del.java_method(:getUsernameField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_username_field()"
    end
    #  Get the name of the field to be used for the password Defaults to DEFAULT_PASSWORD_FIELD
    # @return [String] the passwordField
    def get_password_field
      if !block_given?
        return @j_del.java_method(:getPasswordField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_password_field()"
    end
    #  Get the name of the field to be used for the roles. Defaults to DEFAULT_ROLE_FIELD. Roles are expected to
    #  be saved as JsonArray
    # @return [String] the roleField
    def get_role_field
      if !block_given?
        return @j_del.java_method(:getRoleField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_role_field()"
    end
    #  Get the name of the field to be used for the permissions. Defaults to DEFAULT_PERMISSION_FIELD.
    #  Permissions are expected to be saved as JsonArray
    # @return [String] the permissionField
    def get_permission_field
      if !block_given?
        return @j_del.java_method(:getPermissionField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_permission_field()"
    end
    #  Get the name of the field to be used as property for the username in the method
    #  {::VertxAuthCommon::AuthProvider#authenticate}. Defaults to DEFAULT_CREDENTIAL_USERNAME_FIELD
    # @return [String] the usernameCredentialField
    def get_username_credential_field
      if !block_given?
        return @j_del.java_method(:getUsernameCredentialField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_username_credential_field()"
    end
    #  Get the name of the field to be used as property for the password of credentials in the method
    #  {::VertxAuthCommon::AuthProvider#authenticate}. Defaults to DEFAULT_CREDENTIAL_PASSWORD_FIELD
    # @return [String] the passwordCredentialField
    def get_password_credential_field
      if !block_given?
        return @j_del.java_method(:getPasswordCredentialField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_password_credential_field()"
    end
    #  Get the name of the field to be used for the salt. Only used when {::VertxAuthMongo::HashStrategy#set_salt_style} is
    #  set to 
    # @return [String] the saltField
    def get_salt_field
      if !block_given?
        return @j_del.java_method(:getSaltField, []).call()
      end
      raise ArgumentError, "Invalid arguments when calling get_salt_field()"
    end
    #  The HashStrategy which is used by the current instance
    # @param [::VertxAuthMongo::HashStrategy] hashStrategy the {::VertxAuthMongo::HashStrategy} to be set
    # @return [self]
    def set_hash_strategy(hashStrategy=nil)
      if hashStrategy.class.method_defined?(:j_del) && !block_given?
        @j_del.java_method(:setHashStrategy, [Java::IoVertxExtAuthMongo::HashStrategy.java_class]).call(hashStrategy.j_del)
        return self
      end
      raise ArgumentError, "Invalid arguments when calling set_hash_strategy(hashStrategy)"
    end
    #  The HashStrategy which is used by the current instance
    # @return [::VertxAuthMongo::HashStrategy] the defined instance of {::VertxAuthMongo::HashStrategy}
    def get_hash_strategy
      if !block_given?
        return ::Vertx::Util::Utils.safe_create(@j_del.java_method(:getHashStrategy, []).call(),::VertxAuthMongo::HashStrategy)
      end
      raise ArgumentError, "Invalid arguments when calling get_hash_strategy()"
    end
    #  Insert a new user into mongo in the convenient way
    # @param [String] username the username to be set
    # @param [String] password the passsword in clear text, will be adapted following the definitions of the defined {::VertxAuthMongo::HashStrategy}
    # @param [Array<String>] roles a list of roles to be set
    # @param [Array<String>] permissions a list of permissions to be set
    # @yield the ResultHandler will be provided with the id of the generated record
    # @return [void]
    def insert_user(username=nil,password=nil,roles=nil,permissions=nil)
      if username.class == String && password.class == String && roles.class == Array && permissions.class == Array && block_given?
        return @j_del.java_method(:insertUser, [Java::java.lang.String.java_class,Java::java.lang.String.java_class,Java::JavaUtil::List.java_class,Java::JavaUtil::List.java_class,Java::IoVertxCore::Handler.java_class]).call(username,password,roles.map { |element| element },permissions.map { |element| element },(Proc.new { |ar| yield(ar.failed ? ar.cause : nil, ar.succeeded ? ar.result : nil) }))
      end
      raise ArgumentError, "Invalid arguments when calling insert_user(username,password,roles,permissions)"
    end
  end
end
