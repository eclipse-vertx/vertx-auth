/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.impl.AuthorizationsImpl;
import io.vertx.ext.auth.impl.UserImpl;

/**
 * Represents an authenticates User and contains operations to authorise the user.
 * <p>
 * Please consult the documentation for a detailed explanation.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface User {

  static User create(JsonObject principal) {
    return create(principal, new JsonObject());
  }

  static User create(JsonObject principal, JsonObject attributes) {
    return new UserImpl(principal, attributes);
  }

  /**
   * Gets extra attributes of the user. Attributes contains any attributes related
   * to the outcome of authenticating a user (e.g.: issued date, metadata, etc...)
   *
   * @return a json object with any relevant attribute.
   */
  JsonObject attributes();

  /**
   * Flags this user object to be expired. A User is considered expired if it contains an expiration time and
   * the current clock time is post the expiration date.
   *
   * @return {@code true} if expired
   */
  default boolean expired() {
    return expired(attributes().getInteger("leeway", 0));
  }

  /**
   * Flags this user object to be expired. Expiration takes 3 values in account:
   *
   * <ol>
   *   <li>{@code exp} "expiration" timestamp in seconds.</li>
   *   <li>{@code iat} "issued at" in seconds.</li>
   *   <li>{@code nbf} "not before" in seconds.</li>
   * </ol>
   * A User is considered expired if it contains any of the above and
   * the current clock time does not agree with the parameter value. If the {@link #principal()} do not contain a key
   * then {@link #attributes()} are checked.
   * <p>
   * If all of the properties are not available the user will not expire.
   * <p>
   * Implementations of this interface might relax this rule to account for a leeway to safeguard against
   * clock drifting.
   *
   * @param leeway a greater than zero leeway value.
   * @return {@code true} if expired
   */
  default boolean expired(int leeway) {
    // All dates are of type NumericDate
    // a NumericDate is: numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until
    // the specified UTC date/time, ignoring leap seconds
    final long now = (System.currentTimeMillis() / 1000);

    if (principal().containsKey("exp") || attributes().containsKey("exp")) {
      if (now - leeway >= principal().getLong("exp", attributes().getLong("exp"))) {
        return true;
      }
    }

    if (principal().containsKey("iat") || attributes().containsKey("iat")) {
      Long iat = principal().getLong("iat", attributes().getLong("iat"));
      // issue at must be in the past
      if (iat > now + leeway) {
        return true;
      }
    }

    if (principal().containsKey("nbf") || attributes().containsKey("nbf")) {
      Long nbf = principal().getLong("nbf", attributes().getLong("nbf"));
      // not before must be after now
      if (nbf > now + leeway) {
        return true;
      }
    }

    return false;
  }

  /**
   * Returns user's authorizations that have been previously loaded by the providers.
   *
   * @return authorizations holder for the user.
   */
  default Authorizations authorizations() {
    return new AuthorizationsImpl();
  }

  /**
   * Is the user authorised to
   *
   * @param authority     the authority - what this really means is determined by the specific implementation. It might
   *                      represent a permission to access a resource e.g. `printers:printer34` or it might represent
   *                      authority to a role in a roles based model, e.g. `role:admin`.
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value
   *                      `true` if the they has the authority or `false` otherwise.
   * @return the User to enable fluent use
   */
  @Fluent
  User isAuthorized(Authorization authority, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Is the user authorised to
   *
   * @param authority     the authority - what this really means is determined by the specific implementation. It might
   *                      represent a permission to access a resource e.g. `printers:printer34` or it might represent
   *                      authority to a role in a roles based model, e.g. `role:admin`.
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value
   *                      `true` if the they has the authority or `false` otherwise.
   * @return the User to enable fluent use
   * @deprecated Use typed alternative {@link #isAuthorized(Authorization, Handler)}
   */
  @Fluent
  @Deprecated
  default User isAuthorized(String authority, Handler<AsyncResult<Boolean>> resultHandler) {
    return isAuthorized(
      authority.startsWith("role:") ?
        RoleBasedAuthorization.create(authority.substring(5))
        : WildcardPermissionBasedAuthorization.create(authority), resultHandler);
  }

  /**
   * Is the user authorised to
   *
   * @param authority the authority - what this really means is determined by the specific implementation. It might
   *                  represent a permission to access a resource e.g. `printers:printer34` or it might represent
   *                  authority to a role in a roles based model, e.g. `role:admin`.
   * @return Future handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value
   * `true` if the they has the authority or `false` otherwise.
   * @see User#isAuthorized(Authorization, Handler)
   */
  default Future<Boolean> isAuthorized(Authorization authority) {
    Promise<Boolean> promise = Promise.promise();
    isAuthorized(authority, promise);
    return promise.future();
  }

  /**
   * Is the user authorised to
   *
   * @param authority the authority - what this really means is determined by the specific implementation. It might
   *                  represent a permission to access a resource e.g. `printers:printer34` or it might represent
   *                  authority to a role in a roles based model, e.g. `role:admin`.
   * @return Future handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value
   * `true` if the they has the authority or `false` otherwise.
   * @see User#isAuthorized(String, Handler)
   * @deprecated Use typed alternative {@link #isAuthorized(Authorization)}
   */
  @Deprecated
  default Future<Boolean> isAuthorized(String authority) {
    return isAuthorized(
      authority.startsWith("role:") ?
        RoleBasedAuthorization.create(authority.substring(5))
        : WildcardPermissionBasedAuthorization.create(authority));
  }

  /**
   * The User object will cache any authorities that it knows it has to avoid hitting the
   * underlying auth provider each time.  Use this method if you want to clear this cache.
   *
   * @return the User to enable fluent use
   * @deprecated This method will be removed. Use {@link Authorizations#clear()}
   */
  @Fluent
  @Deprecated
  default User clearCache() {
    authorizations().clear();
    return this;
  }

  /**
   * Get the underlying principal for the User. What this actually returns depends on the implementation.
   * For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
   * <pre>
   *   {
   *     "username", "tim"
   *   }
   * </pre>
   *
   * @return JSON representation of the Principal
   */
  JsonObject principal();

  /**
   * Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
   * after it has been deserialized.
   *
   * @param authProvider the AuthProvider - this must be the same type of AuthProvider that originally created the User
   */
  @Deprecated
  void setAuthProvider(AuthProvider authProvider);
}
