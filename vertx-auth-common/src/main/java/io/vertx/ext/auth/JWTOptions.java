package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

import java.util.List;

@Deprecated
@DataObject
public class JWTOptions extends io.vertx.ext.auth.jose.JWTOptions {

  public JWTOptions() {
    super();
  }

  public JWTOptions(JWTOptions other) {
    super(other);
  }

  public JWTOptions(JsonObject json) {
    super(json);
  }

  public JWTOptions setLeeway(int leeway) {
    return (JWTOptions) super.setLeeway(leeway);
  }

  public JWTOptions setIgnoreExpiration(boolean ignoreExpiration) {
    return (JWTOptions) super.setIgnoreExpiration(ignoreExpiration);
  }

  public JWTOptions setAlgorithm(String algorithm) {
    return (JWTOptions) super.setAlgorithm(algorithm);
  }

  public JWTOptions setHeader(JsonObject header) {
    return (JWTOptions) super.setHeader(header);
  }

  public JWTOptions setNoTimestamp(boolean noTimestamp) {
    return (JWTOptions) super.setNoTimestamp(noTimestamp);
  }

  public JWTOptions setExpiresInSeconds(int expires) {
    return (JWTOptions) super.setExpiresInSeconds(expires);
  }

  public JWTOptions setExpiresInMinutes(int expiresInMinutes) {
    return (JWTOptions) super.setExpiresInMinutes(expiresInMinutes);
  }

  public JWTOptions setAudience(List<String> audience) {
    return (JWTOptions) super.setAudience(audience);
  }

  public JWTOptions addAudience(String audience) {
    return (JWTOptions) super.addAudience(audience);
  }

  public JWTOptions setIssuer(String issuer) {
    return (JWTOptions) super.setIssuer(issuer);
  }

  public JWTOptions setSubject(String subject) {
    return (JWTOptions) super.setSubject(subject);
  }

  @Deprecated
  public JWTOptions setPermissions(List<String> permissions) {
    return (JWTOptions) super.setPermissions(permissions);
  }

  @Deprecated
  public JWTOptions addPermission(String permission) {
    return (JWTOptions) super.addPermission(permission);
  }

  public JWTOptions setNonceAlgorithm(String nonceAlgorithm) {
    return (JWTOptions) super.setNonceAlgorithm(nonceAlgorithm);
  }
}
