package io.vertx.ext.auth.oauth2.rbac;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.RBACHandler;

@VertxGen
public interface MicroProfileRBAC extends RBACHandler {

  static MicroProfileRBAC create() {
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
