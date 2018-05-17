// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package io.vertx.ext.auth.jcasbin.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import org.casbin.jcasbin.main.Enforcer;


/**
 * @author Yang Luo
 */
public class JCasbinUser extends AbstractUser {

  public final static Enforcer enforcer = new Enforcer("examples/authz_model.conf", "examples/authz_policy.csv");

  private final String username;

  public JCasbinUser(String username) {
    this.username = username;
  }

  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    String permTokens[] = permission.split("::");
    String path = permTokens[0];
    String method = permTokens[1];

    if (enforcer.enforce(username, path, method)) {
      resultHandler.handle(Future.succeededFuture(true));
    } else {
      resultHandler.handle(Future.succeededFuture(false));
    }
  }

  @Override
  public JsonObject principal() {
    return new JsonObject()
      .put("username", username);
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
  }
}
