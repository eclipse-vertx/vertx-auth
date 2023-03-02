package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.*;

import java.util.*;

public class AuthorizationPolicyProviderImpl implements AuthorizationPolicyProvider {

  private final String id;
  private final AuthorizationProvider parent;
  private final Map<Authorization, List<Authorization>> policy;

  public AuthorizationPolicyProviderImpl(AuthorizationProvider parent, JsonObject policy) {
    this.parent = parent;
    this.id = parent.getId() + "-policy";
    Map<Authorization, List<Authorization>> tmp = new HashMap<>();
    for (String key : policy.fieldNames()) {
      Object value = policy.getValue(key);
      if (value instanceof JsonArray) {
        List<Authorization> lst = new ArrayList<>();
        for (Object item : (JsonArray) value) {
          if (item instanceof JsonObject) {
            lst.add(AuthorizationConverter.decode((JsonObject) item));
          } else {
            throw new IllegalArgumentException("Invalid policy definition");
          }
        }
        tmp.put(WildcardPermissionBasedAuthorization.create(key), lst);
      } else if (value instanceof JsonObject) {
        tmp.put(WildcardPermissionBasedAuthorization.create(key), Collections.singletonList(AuthorizationConverter.decode(policy.getJsonObject(key))));
      } else {
        throw new IllegalArgumentException("Invalid policy definition");
      }
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
            authorizations.addAll(policy.get(authn));
          }
        }
        if (authorizations != null) {
          user.authorizations().add(id, authorizations);
        }
      });
  }
}
