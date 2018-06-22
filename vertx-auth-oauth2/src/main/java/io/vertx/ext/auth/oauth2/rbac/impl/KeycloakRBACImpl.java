package io.vertx.ext.auth.oauth2.rbac.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2User;
import io.vertx.ext.auth.oauth2.rbac.KeycloakRBAC;

import java.util.Collections;
import java.util.Objects;

public class KeycloakRBACImpl implements KeycloakRBAC {

  private static final JsonObject EMPTY_JSON = new JsonObject(Collections.EMPTY_MAP);
  private static final JsonArray EMPTY_ARRAY = new JsonArray(Collections.EMPTY_LIST);

  private final OAuth2ClientOptions options;

  public KeycloakRBACImpl(OAuth2ClientOptions options) {
    if (options == null) {
      throw new IllegalArgumentException("options is a required argument");
    }
    this.options = options;
  }

  /**
   * Determine if this token has an associated role.
   * <p>
   * This method is only functional if the token is constructed
   * with a `clientId` parameter.
   * <p>
   * The parameter matches a role specification using the following rules:
   * <p>
   * - If the name contains no colons, then the name is taken as the entire
   * name of a role within the current application, as specified via
   * `clientId`.
   * - If the name starts with the literal `realm:`, the subsequent portion
   * is taken as the name of a _realm-level_ role.
   * - Otherwise, the name is split at the colon, with the first portion being
   * taken as the name of an arbitrary application, and the subsequent portion
   * as the name of a role with that app.
   *
   * @param authority    The role name specifier.
   * @param handler `true` if this token has the specified role, otherwise `false`.
   */
  @Override
  public void isAuthorized(OAuth2User user, String authority, Handler<AsyncResult<Boolean>> handler) {

    JsonObject accessToken = user.accessToken();

    if (accessToken == null) {
      handler.handle(Future.failedFuture("AccessToken is not a valid JWT"));
      return;
    }

    String[] parts = authority.split(":");

    if (parts.length == 1) {
      handler.handle(Future.succeededFuture(hasApplicationRole(accessToken, options.getClientID(), parts[0])));
      return;
    }

    if ("realm".equals(parts[0])) {
      handler.handle(Future.succeededFuture(hasRealmRole(accessToken, parts[1])));
      return;
    }

    handler.handle(Future.succeededFuture(hasApplicationRole(accessToken, parts[0], parts[1])));
  }

  /**
   * Determine if this token has an associated specific application role.
   * <p>
   * Even if `clientId` is not set, this method may be used to explicitly test
   * roles for any given application.
   *
   * @param appName  The identifier of the application to test.
   * @param roleName The name of the role within that application to test.
   * @return `true` if this token has the specified role, otherwise `false`.
   */
  private boolean hasApplicationRole(JsonObject accessToken, String appName, String roleName) {
    if (accessToken == null) {
      return false;
    }

    JsonObject appRoles = accessToken
      .getJsonObject("resource_access", EMPTY_JSON)
      .getJsonObject(appName);

    if (appRoles == null) {
      return false;
    }

    return appRoles
      .getJsonArray("roles", EMPTY_ARRAY)
      .contains(roleName);
  }

  /**
   * Determine if this token has an associated specific realm-level role.
   * <p>
   * Even if `clientId` is not set, this method may be used to explicitly test
   * roles for the realm.
   *
   * @param roleName The name of the role within that application to test.
   * @return `true` if this token has the specified role, otherwise `false`.
   */
  private boolean hasRealmRole(JsonObject accessToken, String roleName) {
    if (accessToken == null) {
      return false;
    }

    return accessToken
      .getJsonObject("realm_access", EMPTY_JSON)
      .getJsonArray("roles", EMPTY_ARRAY)
      .contains(roleName);
  }
}
