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

  private final String[] principalPath;
  private final Map<String, List<Authorization>> policy;

  public AuthorizationPolicyProviderImpl(String principalPath, JsonObject policy) {
    Objects.requireNonNull(principalPath);
    Objects.requireNonNull(policy);

    this.principalPath = principalPath.split("/");
    Map<String, List<Authorization>> tmp = new HashMap<>();
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
        tmp.put(key, lst);
      } else if (value instanceof JsonObject) {
        tmp.put(key, Collections.singletonList(AuthorizationConverter.decode(policy.getJsonObject(key))));
      } else {
        throw new IllegalArgumentException("Invalid policy definition");
      }
    }
    this.policy = Collections.unmodifiableMap(tmp);
  }

  @Override
  public String getId() {
    return "policy";
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizations(user)
      .onComplete(handler);
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    Object claims = user.principal();
    for (String segment : principalPath) {
      if (segment.equals("")) {
        continue;
      }
      if (claims instanceof JsonObject) {
        claims = ((JsonObject) claims).getValue(segment);
      } else {
        return Future.failedFuture("Missing principal path");
      }
    }
    if (claims instanceof JsonArray) {
      Set<Authorization> authorizations = new HashSet<>();
      for (Object claim : (JsonArray) claims) {
        if (claim instanceof String) {
          List<Authorization> authz = policy.get(claim);
          if (authz != null) {
            authorizations.addAll(authz);
          }
        }
      }
      user.authorizations().add(getId(), authorizations);
      return Future.succeededFuture();
    } else {
      // nothing can be extracted
      return Future.succeededFuture();
    }
  }
}
