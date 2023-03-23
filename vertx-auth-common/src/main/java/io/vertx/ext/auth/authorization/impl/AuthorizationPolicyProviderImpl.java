package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.*;

import java.util.*;

public class AuthorizationPolicyProviderImpl implements AuthorizationPolicyProvider {

  private final String id;
  private final AuthorizationProvider parent;
  private final Map<Authorization, Authorization> policy;

  public AuthorizationPolicyProviderImpl(AuthorizationProvider parent, JsonObject policy) {
    this.parent = parent;
    this.id = parent.getId() + "-policy";
    Map<Authorization, Authorization> tmp = new HashMap<>();
    for (String key : policy.fieldNames()) {
      tmp.put(WildcardPermissionBasedAuthorization.create(key), AuthorizationConverter.decode(policy.getJsonObject(key)));
    }
    this.policy = Collections.unmodifiableMap(tmp);
  }

  @Override
  public String getId() {
    return id;
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizations(user)
      .onComplete(handler);
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    return parent
      .getAuthorizations(user)
      .onSuccess(v -> {
        Set<Authorization> authorizations = null;
        for (Authorization authn : user.authorizations().get(parent.getId())) {
          if (policy.containsKey(authn)) {
            if (authorizations == null) {
              authorizations = new HashSet<>();
            }
            authorizations.add(policy.get(authn));
          }
        }
        if (authorizations != null) {
          user.authorizations().add(id, authorizations);
        }
      });
  }
}
