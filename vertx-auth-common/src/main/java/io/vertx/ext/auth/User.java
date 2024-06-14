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
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;
import io.vertx.ext.auth.impl.UserImpl;

/**
 * Represents an authenticates User and contains operations to authorise the user.
 * <p>
 * Please consult the documentation for a detailed explanation.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Deprecated
@VertxGen
public interface User extends io.vertx.ext.auth.user.User {

  /**
   * Factory for user instances that are single string. The credentials will be added to the principal
   * of this instance. As nothing can be said about the credentials no validation will be done.
   *
   * Will create a principal with a property {@code "username"} with the name as value.
   *
   * @param username the value for this user
   * @return user instance
   */
  static User fromName(String username) {
    return create(new JsonObject().put("username", username));
  }

  /**
   * Factory for user instances that are single string. The credentials will be added to the principal
   * of this instance. As nothing can be said about the credentials no validation will be done.
   *
   * Will create a principal with a property {@code "access_token"} with the name as value.
   *
   * @param token the value for this user
   * @return user instance
   */
  static User fromToken(String token) {
    return create(new JsonObject().put("access_token", token));
  }

  /**
   * Factory for user instances that are free form. The credentials will be added to the principal
   * of this instance. As nothing can be said about the credentials no validation will be done.
   *
   * @param principal the free form json principal
   * @return user instance
   */
  static User create(JsonObject principal) {
    return create(principal, new JsonObject());
  }

  /**
   * Factory for user instances that are free form. The credentials will be added to the principal
   * of this instance. As nothing can be said about the credentials no validation will be done.
   *
   * @param principal the free form json principal
   * @param attributes the free form json attributes that further describe the principal
   * @return user instance
   */
  static User create(JsonObject principal, JsonObject attributes) {
    return new UserImpl(principal, attributes);
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
  @Deprecated
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
    return (User) io.vertx.ext.auth.user.User.super.isAuthorized(authority, resultHandler);
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
    return (User) io.vertx.ext.auth.user.User.super.clearCache();
  }

  /**
   * Merge the principal and attributes of a second user into this object properties.
   *
   * It is important to notice that the principal merges by replacing existing keys with the new values, while the
   * attributes (as they represent decoded data) are accumulated at the root level.
   *
   * This means that given:
   *
   * <pre>{@code
   * userA = {
   *   attributes: {
   *     roles: [ 'read' ]
   *   }
   * }
   *
   * userB = {
   *   attributes: {
   *     roles: [ 'write' ]
   *   }
   * }
   * }</pre>
   *
   * When performing a merge of {@code userA} with {@code userB}, you will get:
   *
   * <pre>{@code
   * userA.merge(userB);
   * // results in
   * {
   *   attributes: {
   *     roles: [ 'read', 'write' ]
   *   }
   * }
   * }</pre>
   *
   * @param other the other user to merge
   * @return fluent self
   */
  @Fluent
  User merge(io.vertx.ext.auth.user.User other);
}
