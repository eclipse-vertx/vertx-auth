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
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jcasbin.JCasbinAuth;


/**
 * An implementation of {@link JCasbinAuth}
 *
 * @author Yang Luo
 */
public class JCasbinAuthImpl implements JCasbinAuth {

  public JCasbinAuthImpl(Vertx vertx) {
  }

  // Checks the correctness of user name and password as you like.
  private boolean checkUserPassword(String username, String password) {
    return true;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    String username = authInfo.getString("username");
    String password = authInfo.getString("password");

    boolean authenticated = checkUserPassword(username, password);

    if (authenticated) {
      resultHandler.handle(Future.succeededFuture(new JCasbinUser(username)));
    } else {
      resultHandler.handle(Future.failedFuture("Bad response"));
    }
  }
}
