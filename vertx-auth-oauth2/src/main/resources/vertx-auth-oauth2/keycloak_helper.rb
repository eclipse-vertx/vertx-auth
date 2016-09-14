require 'vertx/util/utils.rb'
# Generated from io.vertx.ext.auth.oauth2.KeycloakHelper
module VertxAuthOauth2
  #  Helper class for processing Keycloak principal.
  class KeycloakHelper
    # @private
    # @param j_del [::VertxAuthOauth2::KeycloakHelper] the java delegate
    def initialize(j_del)
      @j_del = j_del
    end

    # @private
    # @return [::VertxAuthOauth2::KeycloakHelper] the underlying java delegate
    def j_del
      @j_del
    end

    #  Get raw `id_token` string from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [String] the raw id token string
    def self.raw_id_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:rawIdToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling raw_id_token(principal)"
    end

    #  Get decoded `id_token` from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [Hash{String => Object}] the id token
    def self.id_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:idToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)) != nil ? JSON.parse(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:idToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)).encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling id_token(principal)"
    end

    #  Get raw `access_token` string from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [String] the raw access token string
    def self.raw_access_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:rawAccessToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling raw_access_token(principal)"
    end

    #  Get decoded `access_token` from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [Hash{String => Object}] the access token
    def self.access_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:accessToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)) != nil ? JSON.parse(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:accessToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)).encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling access_token(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [Fixnum]
    def self.auth_time(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:authTime, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling auth_time(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.session_state(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:sessionState, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling session_state(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.acr(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:acr, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling acr(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.name(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:name, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling name(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.email(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:email, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling email(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.preferred_username(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:preferredUsername, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling preferred_username(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.nick_name(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:nickName, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling nick_name(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [Set<String>]
    def self.allowed_origins(principal=nil)
      if principal.class == Hash && !block_given?
        return ::Vertx::Util::Utils.to_set(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:allowedOrigins, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))).map! { |elt| elt }
      end
      raise ArgumentError, "Invalid arguments when calling allowed_origins(principal)"
    end

    #  Parse the token string with base64 decoder.
    #  This will only obtain the "payload" part of the token.
    # @param [String] token token string
    # @return [Hash{String => Object}] token payload json object
    def self.parse_token(token=nil)
      if token.class == String && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:parseToken, [Java::java.lang.String.java_class]).call(token) != nil ? JSON.parse(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:parseToken, [Java::java.lang.String.java_class]).call(token).encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling parse_token(token)"
    end
  end
end
