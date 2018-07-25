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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.shareddata.impl.ClusterSerializable;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * Useful base class for implementing a User object.
 * <p>
 * This class handles the caching logic so you can concentrate on the actual authorisation logic.
 * <p>
 * Just implement the abstract methods in your concrete sub-class.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public abstract class AbstractUser implements User, ClusterSerializable {

  private final Set<String> cachedPermissions = new HashSet<>();

  @Override
  public User isAuthorized(String authority, Handler<AsyncResult<Boolean>> resultHandler) {
    if (cachedPermissions.contains(authority)) {
      resultHandler.handle(Future.succeededFuture(true));
    } else {
      doIsPermitted(authority, res -> {
        if (res.succeeded()) {
          if (res.result()) {
            cachedPermissions.add(authority);
          }
        }
        resultHandler.handle(res);
      });
    }
    return this;
  }

  @Override
  public User clearCache() {
    cachedPermissions.clear();
    return this;
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    writeStringSet(buff, cachedPermissions);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = readStringSet(buffer, cachedPermissions, pos);
    return pos;
  }

  public boolean cachePermission(String authority) {
    return cachedPermissions.add(authority);
  }

  protected abstract void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler);

  private void writeStringSet(Buffer buff, Set<String> set) {
    buff.appendInt(set == null ? 0 : set.size());
    if (set != null) {
      for (String entry : set) {
        byte[] bytes = entry.getBytes(StandardCharsets.UTF_8);
        buff.appendInt(bytes.length).appendBytes(bytes);
      }
    }
  }

  private int readStringSet(Buffer buffer, Set<String> set, int pos) {
    int num = buffer.getInt(pos);
    pos += 4;
    for (int i = 0; i < num; i++) {
      int len = buffer.getInt(pos);
      pos += 4;
      byte[] bytes = buffer.getBytes(pos, pos + len);
      pos += len;
      set.add(new String(bytes, StandardCharsets.UTF_8));
    }
    return pos;
  }
}
