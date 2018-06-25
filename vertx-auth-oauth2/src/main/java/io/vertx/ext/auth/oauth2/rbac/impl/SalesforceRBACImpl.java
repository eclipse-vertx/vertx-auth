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
package io.vertx.ext.auth.oauth2.rbac.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2RBAC;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class SalesforceRBACImpl implements OAuth2RBAC {

  private final OAuth2ClientOptions config;

  public SalesforceRBACImpl(OAuth2ClientOptions options) {
    this.config = options;
  }

  @Override
  public void isAuthorized(AccessToken user, String authority, Handler<AsyncResult<Boolean>> handler) {
    String id = user.principal().getString("id");
    // TODO: id not null, exists / etc...
    id = id.substring(id.lastIndexOf('/'));
    // TODO: this probably should be a configuration right?
    // TODO: should we escape the id? SQL injection?
    final String query = "select Assignee.UserName, Assignee.Name, Assignee.Alias, Assignee.UserType, Assignee.Profile.Name, PermissionSet.Name, Assignee.UserRole.Name  from PermissionSetAssignment where Assignee.Id = '" + id + "'";


    user.fetch(config.getSite() + "/services/data/v43.0/query/?q=" + escape(query), fetch -> {
      if (fetch.failed()) {
        handler.handle(Future.failedFuture(fetch.cause()));
        return;
      }

      final OAuth2Response reply = fetch.result();

      if (reply.body() == null || reply.body().length() == 0) {
        handler.handle(Future.failedFuture("No Body"));
        return;
      }

      JsonObject json;

      if (reply.is("application/json")) {
        try {
          json = reply.jsonObject();

          // TODO: need to parse the response
          // TODO: validation should assert totalSize, done
          System.out.println(json);

          // TODO: do the real work here...

          // TODO: it should return true in user has role...
          handler.handle(Future.succeededFuture(false));
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      } else {
        handler.handle(Future.failedFuture("Cannot handle Content type: " + reply.headers().get("Content-Type")));
      }
    });
  }

  private static String escape(String string) {
    try {
      return URLEncoder.encode(string, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}
