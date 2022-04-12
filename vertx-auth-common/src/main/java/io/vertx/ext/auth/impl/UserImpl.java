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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.impl.ClusterSerializable;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.Authorizations;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.authorization.impl.AuthorizationsImpl;

import java.util.Collections;
import java.util.Objects;

/**
 * Default implementation of a User
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
public class UserImpl implements User, ClusterSerializable {
  // set of authorizations
  private Authorizations authorizations;
  // attributes
  private JsonObject attributes;
  // the principal of the user
  private JsonObject principal;

  public UserImpl() {
    // for ClusterSerializable
  }

  public UserImpl(JsonObject principal, JsonObject attributes) {
    this.principal = Objects.requireNonNull(principal);
    this.attributes = attributes;
    this.authorizations = new AuthorizationsImpl();
  }

  @Override
  public Authorizations authorizations() {
    return authorizations;
  }

  @Override
  public JsonObject attributes() {
    return attributes;
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
    return
      Objects.equals(authorizations, other.authorizations) &&
        Objects.equals(principal, other.principal) &&
        Objects.equals(attributes, other.attributes);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorizations, principal, attributes);
  }

  @Override
  public User isAuthorized(Authorization authorization, Handler<AsyncResult<Boolean>> resultHandler) {
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
  public User merge(User other) {
    if (other == null) {
      return this;
    }

    principal()
      // merge in the rhs
      .mergeIn(other.principal());

    JsonObject attrs = attributes();
    JsonObject otherAttrs = other.attributes();

    if (attrs == null) {
      if (otherAttrs != null) {
        // do not notify the state of the previous user
        attributes = otherAttrs.copy();
      }
    } else {
      if (otherAttrs != null) {
        for (String key : otherAttrs.fieldNames()) {
          Object lhsValue = attrs.getValue(key);
          Object rhsValue = otherAttrs.getValue(key);
          // accumulate
          if (lhsValue == null) {
            attrs.put(key, rhsValue instanceof JsonArray ? new JsonArray().addAll((JsonArray) rhsValue) : rhsValue);
          } else if (lhsValue instanceof JsonArray) {
            if (rhsValue instanceof JsonArray) {
              ((JsonArray) lhsValue).addAll((JsonArray) rhsValue);
            } else {
              ((JsonArray) lhsValue).add(rhsValue);
            }
          } else {
            if (rhsValue instanceof JsonArray) {
              attrs.put(key, new JsonArray().add(lhsValue).addAll((JsonArray) rhsValue));
            } else {
              attrs.put(key, new JsonArray().add(lhsValue).add(rhsValue));
            }
          }
        }
      }
    }
    return this;
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
    this.attributes = readUser.attributes();
    return read;
  }
}
