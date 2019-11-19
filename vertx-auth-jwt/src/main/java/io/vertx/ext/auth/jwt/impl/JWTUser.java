/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth.jwt.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;

import java.nio.charset.StandardCharsets;

/**
 * @author Paulo Lopes
 */
public class JWTUser extends AbstractUser {

  private static final Logger log = LoggerFactory.getLogger(JWTUser.class);

  private JsonObject jwtToken;
  private JsonArray permissions;

  public JWTUser() {
    // required if the object is serialized, however this is not a good idea
    // because JWT are supposed to be used in stateless environments
    log.info("You are probably serializing the JWT User, JWT are supposed to be used in stateless servers!");
  }

  public JWTUser(JsonObject jwtToken, String permissionsClaimKey) {
    this.jwtToken = jwtToken;

    if(permissionsClaimKey.contains("/")) {
      getNestedJsonValue(jwtToken, permissionsClaimKey);
    } else {
      this.permissions = jwtToken.getJsonArray(permissionsClaimKey, null);
    }

  }

  private void getNestedJsonValue(JsonObject jwtToken, String permissionsClaimKey) {
    String[] keys = permissionsClaimKey.split("/");
    JsonObject obj = null;
    for(int i = 0; i < keys.length; i++) {
        if(i == 0) {
          obj = jwtToken.getJsonObject(keys[i]);
        } else if (i == keys.length -1) {
          if(obj != null) {
            this.permissions = obj.getJsonArray(keys[i]);
          }
        } else {
          if(obj != null) {
            obj = obj.getJsonObject(keys[i]);
          }
        }
    }
  }

  @Override
  public JsonObject principal() {
    return jwtToken;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    // NOOP - JWT tokens are self contained :)
  }

  @Override
  public void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> handler) {
    if (permissions != null) {
      for (Object jwtPermission : permissions) {
        if (permission.equals(jwtPermission)) {
          handler.handle(Future.succeededFuture(true));
          return;
        }
      }
    }

    log.debug("User has no permission [" + permission + "]");
    handler.handle(Future.succeededFuture(false));
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    byte[] bytes;

    bytes = jwtToken.encode().getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length);
    buff.appendBytes(bytes);

    if (permissions != null) {
      bytes = permissions.encode().getBytes(StandardCharsets.UTF_8);
      buff.appendInt(bytes.length);
      buff.appendBytes(bytes);
    } else {
      buff.appendInt(0);
    }
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = super.readFromBuffer(pos, buffer);
    int len;
    byte[] bytes;

    len = buffer.getInt(pos);
    pos += 4;
    bytes = buffer.getBytes(pos, pos + len);
    jwtToken = new JsonObject(new String(bytes, StandardCharsets.UTF_8));
    pos += len;

    len = buffer.getInt(pos);
    pos += 4;
    if (len > 0) {
      bytes = buffer.getBytes(pos, pos + len);
      permissions = new JsonArray(new String(bytes, StandardCharsets.UTF_8));
      pos += len;
    }
    return pos;
  }
}
