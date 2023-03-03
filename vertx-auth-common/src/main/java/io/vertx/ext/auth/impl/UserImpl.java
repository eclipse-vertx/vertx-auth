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

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.ClusterSerializable;
import io.vertx.ext.auth.authorization.Authorizations;
import io.vertx.ext.auth.User;
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
  public JsonObject principal() {
    return principal;
  }

  @Override
  public User merge(User other) {
    if (other == null) {
      return this;
    }

    // hold a reference before we mutate the principal bellow
    JsonArray amr = principal().getJsonArray("amr");
    JsonArray otherAmr = other.principal().getJsonArray("amr");

    principal()
      // merge in the rhs
      .mergeIn(other.principal());

    // process "amr"
    if (amr == null) {
      if (otherAmr != null) {
        amr = otherAmr.copy();
      }
    } else {
      if (otherAmr != null) {
        amr = amr.copy();
        for (Object el : otherAmr) {
          if (!amr.contains(el)) {
            amr.add(el);
          }
        }
      }
    }

    // merge also means mfa
    if (amr == null) {
      principal.put("amr", Collections.singletonList("mfa"));
    } else {
      amr = amr.copy();
      if (!amr.contains("mfa")) {
        amr.add("mfa");
      }
      principal.put("amr", amr);
    }

    // process the attributes

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
            attrs.put(key, rhsValue instanceof JsonArray ? new JsonArray().add(rhsValue) : rhsValue);
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
