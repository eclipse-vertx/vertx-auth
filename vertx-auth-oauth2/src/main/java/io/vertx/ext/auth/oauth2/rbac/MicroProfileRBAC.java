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
package io.vertx.ext.auth.oauth2.rbac;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2RBAC;

/**
 * Implementation of the Microprofile MP-JWT 1.1 RBAC based on the access token groups key.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>.
 */
@VertxGen
public interface MicroProfileRBAC {

  /**
   * Factory method to create a RBAC handler for tokens adhering to the MP-JWT 1.1 spec.
   * @return a RBAC validator
   */
  static OAuth2RBAC create() {
    return (user, authority, handler) -> {
      JsonObject accessToken = user.accessToken();

      if (accessToken == null) {
        handler.handle(Future.failedFuture("AccessToken is not a valid JWT"));
        return;
      }

      // the spec MP-JWT 1.1 defines a custom grant called "groups"
      final JsonArray groups = accessToken.getJsonArray("groups");
      // This MP-JWT custom claim is the list of group names that have been assigned to the principal of the MP-JWT.
      // This typically will required a mapping at the application container level to application deployment roles,
      // but a a one-to-one between group names and application role names is required to be performed in addition
      // to any other mapping.

      if (groups == null || groups.size() == 0) {
        handler.handle(Future.succeededFuture(false));
        return;
      }

      // verify if the groups claim contains the required authority
      handler.handle(Future.succeededFuture(groups.contains(authority)));
    };
  }
}
