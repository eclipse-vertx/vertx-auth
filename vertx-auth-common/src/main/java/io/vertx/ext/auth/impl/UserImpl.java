/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.impl;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.impl.ClusterSerializable;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.PermissionBasedAuthorization;
import io.vertx.ext.auth.RoleBasedAuthorization;
import io.vertx.ext.auth.User;

/**
 * Default implementation of a User
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
public class UserImpl implements User, ClusterSerializable {

  // set of authorizations
  private Set<Authorization> authorizations;
  // the principal of the user
  private JsonObject principal;

  public UserImpl() {
    // for ClusterSerializable
  }

  public UserImpl(JsonObject principal) {
    this.principal = Objects.requireNonNull(principal);
    this.authorizations = new HashSet<>();
  }

  @Override
  public Set<Authorization> authorizations() {
    return authorizations;
  }

  @Override
  public User clearCache() {
    authorizations.clear();
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    UserImpl other = (UserImpl) obj;
    return Objects.equals(authorizations, other.authorizations) && Objects.equals(principal, other.principal);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorizations, principal);
  }

  @Override
  public User isAuthorized(String authority, Handler<AsyncResult<Boolean>> resultHandler) {
    Objects.requireNonNull(authority);
    Objects.requireNonNull(resultHandler);

    return isAuthorized(authority.startsWith("roles:") ? RoleBasedAuthorization.create(authority.substring(6))
        : PermissionBasedAuthorization.create(authority), resultHandler);
  }

  // TODO: remove this method
  private User isAuthorized(Authorization authorization, Handler<AsyncResult<Boolean>> resultHandler) {
    Objects.requireNonNull(authorization);
    Objects.requireNonNull(resultHandler);

    AuthorizationContext context = new AuthorizationContextImpl(this);
    resultHandler.handle(Future.succeededFuture(authorization.match(context)));
    return this;
  }

  @Override
  public JsonObject principal() {
    return principal;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    // do nothing for now
  }

  @Override
  public void writeToBuffer(Buffer buffer) {
    UserConverter.encode(this).writeToBuffer(buffer);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    JsonObject jsonObject = new JsonObject();
    int read = jsonObject.readFromBuffer(pos, buffer);
    User readUser = UserConverter.decode(jsonObject);
    this.principal = readUser.principal();
    this.authorizations = readUser.authorizations();
    return read;
  }
}
