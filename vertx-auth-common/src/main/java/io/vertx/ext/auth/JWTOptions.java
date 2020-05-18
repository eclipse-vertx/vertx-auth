package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@DataObject(generateConverter = true)
public class JWTOptions {

  private static final JsonObject EMPTY = new JsonObject(Collections.emptyMap());
  private static final String DEFAULT_SCOPE_DELIMITER = " ";

  private int leeway = 0;
  private boolean ignoreExpiration;
  private String algorithm = "HS256";
  private JsonObject header = EMPTY;
  private boolean noTimestamp;
  private int expiresInSeconds;
  private List<String> audience;
  private String issuer;
  private String subject;
  private List<String> permissions;
  private List<String> scopes;
  private String scopeDelimiter;

  public JWTOptions() {

  }

  public JWTOptions(JsonObject json) {
    JWTOptionsConverter.fromJson(json, this);
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    JWTOptionsConverter.toJson(this, json);
    return json;
  }

  public int getLeeway() {
    return leeway;
  }

  public JWTOptions setLeeway(int leeway) {
    this.leeway = leeway;
    return this;
  }

  public boolean isIgnoreExpiration() {
    return ignoreExpiration;
  }

  public JWTOptions setIgnoreExpiration(boolean ignoreExpiration) {
    this.ignoreExpiration = ignoreExpiration;
    return this;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public JWTOptions setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  public JsonObject getHeader() {
    return header;
  }

  public JWTOptions setHeader(JsonObject header) {
    this.header = header;
    return this;
  }

  public boolean isNoTimestamp() {
    return noTimestamp;
  }

  public JWTOptions setNoTimestamp(boolean noTimestamp) {
    this.noTimestamp = noTimestamp;
    return this;
  }

  public int getExpiresInSeconds() {
    return expiresInSeconds;
  }

  public JWTOptions setExpiresInSeconds(int expiresInSeconds) {
    this.expiresInSeconds = expiresInSeconds;
    return this;
  }

  public JWTOptions setExpiresInMinutes(int expiresInMinutes) {
    this.expiresInSeconds = expiresInMinutes * 60;
    return this;
  }

  public List<String> getAudience() {
    return audience;
  }

  public JWTOptions setAudience(List<String> audience) {
    this.audience = audience;
    return this;
  }

  public JWTOptions addAudience(String audience) {
    if (this.audience == null) {
      this.audience = new ArrayList<>();
    }
    this.audience.add(audience);
    return this;
  }

  public String getIssuer() {
    return issuer;
  }

  public JWTOptions setIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public String getSubject() {
    return subject;
  }

  public JWTOptions setSubject(String subject) {
    this.subject = subject;
    return this;
  }

  /**
   * The permissions of this token.
   *
   * @param permissions the permissions for this token that will be used for AuthZ
   * @return fluent API
   */
  public JWTOptions setPermissions(List<String> permissions) {
    this.permissions = permissions;
    return this;
  }

  /**
   * Add a permission to this token.
   *
   * @param permission permission for this token that will be used for AuthZ
   * @return fluent API
   */
  public JWTOptions addPermission(String permission) {
    if (this.permissions == null) {
      this.permissions = new ArrayList<>();
    }
    this.permissions.add(permission);
    return this;
  }

  public List<String> getPermissions() {
    return permissions;
  }

  /**
   * @deprecated use the authorization api {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
   */
  @Deprecated
  public JWTOptions setScopes(List<String> scopes) {
    this.scopes = scopes;
    return this;
  }

  /**
   * @deprecated use the authorization api {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
   */
  @Deprecated
  public JWTOptions addScope(String scope) {
    if (this.scopes == null) {
      this.scopes = new ArrayList<>();
    }
    this.scopes.add(scope);
    return this;
  }

  /**
   * @deprecated use the authorization api {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
   */
  @Deprecated
  public List<String> getScopes() {
    return scopes;
  }

  /**
   * @deprecated use the authorization api {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
   */
  @Deprecated
  public String getScopeDelimiter() {
    return scopeDelimiter!=null?scopeDelimiter:DEFAULT_SCOPE_DELIMITER;
  }

  /**
   * @deprecated use the authorization api {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
   */
  @Deprecated
  public JWTOptions withScopeDelimiter(String scopeDelimiter) {
    this.scopeDelimiter = scopeDelimiter;
    return this;
  }

  /**
   * @deprecated use the authorization api {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
   */
  @Deprecated
  public boolean hasScopeDelimiter() {
    return this.scopeDelimiter!=null;
  }
}
