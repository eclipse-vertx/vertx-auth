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
    def self.get_raw_id_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getRawIdToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_raw_id_token(principal)"
    end

    #  Get decoded `id_token` from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [Hash{String => Object}] the id token
    def self.get_id_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getIdToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)) != nil ? JSON.parse(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getIdToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)).encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling get_id_token(principal)"
    end

    #  Get raw `access_token` string from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [String] the raw access token string
    def self.get_raw_access_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getRawAccessToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_raw_access_token(principal)"
    end

    #  Get decoded `access_token` from the principal.
    # @param [Hash{String => Object}] principal user principal
    # @return [Hash{String => Object}] the access token
    def self.get_access_token(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getAccessToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)) != nil ? JSON.parse(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getAccessToken, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal)).encode) : nil
      end
      raise ArgumentError, "Invalid arguments when calling get_access_token(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [Fixnum]
    def self.get_auth_time(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getAuthTime, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_auth_time(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.get_session_state(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getSessionState, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_session_state(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.get_acr(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getAcr, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_acr(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.get_name(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getName, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_name(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.get_email(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getEmail, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_email(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.get_preferred_username(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getPreferredUsername, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_preferred_username(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [String]
    def self.get_nick_name(principal=nil)
      if principal.class == Hash && !block_given?
        return Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getNickName, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))
      end
      raise ArgumentError, "Invalid arguments when calling get_nick_name(principal)"
    end

    # @param [Hash{String => Object}] principal
    # @return [Set<String>]
    def self.get_allowed_origins(principal=nil)
      if principal.class == Hash && !block_given?
        return ::Vertx::Util::Utils.to_set(Java::IoVertxExtAuthOauth2::KeycloakHelper.java_method(:getAllowedOrigins, [Java::IoVertxCoreJson::JsonObject.java_class]).call(::Vertx::Util::Utils.to_json_object(principal))).map! { |elt| elt }
      end
      raise ArgumentError, "Invalid arguments when calling get_allowed_origins(principal)"
    end

    #  Parse the token string with base64 encoder.
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
