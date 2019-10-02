/*
 * Copyright 2019 Red Hat, Inc.
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
package io.vertx.ext.auth.webauthn.impl;

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
public class WebAuthNUser extends AbstractUser {

  private static final Logger log = LoggerFactory.getLogger(WebAuthNUser.class);

  private JsonObject principal;

  public WebAuthNUser() {
    // required if the object is serialized
  }

  public WebAuthNUser(JsonObject principal) {
    this.principal = principal;
  }

  @Override
  public JsonObject principal() {
    return principal;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    // NOOP - WebAuthN principals are self contained :)
  }

  @Override
  public void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> handler) {
    log.debug("User has no permission [" + permission + "]");
    handler.handle(Future.succeededFuture(false));
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    byte[] bytes = principal.encode().getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length);
    buff.appendBytes(bytes);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = super.readFromBuffer(pos, buffer);
    int len = buffer.getInt(pos);
    pos += 4;
    byte[] bytes = buffer.getBytes(pos, pos + len);
    principal = new JsonObject(new String(bytes, StandardCharsets.UTF_8));
    pos += len;

    return pos;
  }
}
