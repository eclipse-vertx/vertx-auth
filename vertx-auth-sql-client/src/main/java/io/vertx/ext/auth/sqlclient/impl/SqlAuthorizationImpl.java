package io.vertx.ext.auth.sqlclient.impl;

import io.vertx.core.Future;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.sqlclient.SqlAuthorization;
import io.vertx.ext.auth.sqlclient.SqlAuthorizationOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class SqlAuthorizationImpl implements SqlAuthorization {

  private final SqlAuthorizationOptions options;
  private final SqlClient client;

  public SqlAuthorizationImpl(SqlClient client, SqlAuthorizationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
  }

  @Override
  public String getId() {
    return "sql-client";
  }

  private Future<Set<Authorization>> getRoles(String username) {
    if (options.getRolesQuery() != null) {
      return client.preparedQuery(options.getRolesQuery())
        .execute(Tuple.of(username))
        .compose(rows -> {
          Set<Authorization> authorizations = new HashSet<>();
          for (Row row : rows) {
            String role = row.getString(0);
            authorizations.add(RoleBasedAuthorization.create(role));
          }
          return Future.succeededFuture(authorizations);
        });
    } else {
      return Future.succeededFuture(Collections.emptySet());
    }
  }

  private Future<Set<Authorization>> getPermissions(String username) {
    if (options.getPermissionsQuery() != null) {
      return client.preparedQuery(options.getPermissionsQuery())
        .execute(Tuple.of(username))
        .compose(rows -> {
          Set<Authorization> authorizations = new HashSet<>();
          for (Row row : rows) {
            String permission = row.getString(0);
            authorizations.add(PermissionBasedAuthorization.create(permission));
          }
          return Future.succeededFuture(authorizations);
        });
    } else {
      return Future.succeededFuture(Collections.emptySet());
    }
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    String username = user.principal().getString("username");
    if (username != null) {
      return getRoles(username)
        .compose(roles -> {
          Set<Authorization> authorizations = new HashSet<>(roles);
          return getPermissions(username)
            .onSuccess(permissions -> {
              authorizations.addAll(permissions);
              user.authorizations().add(getId(), authorizations);
            })
            .mapEmpty();
        });
    } else {
      return Future.failedFuture("Couldn't get the username from the principal");
    }
  }
}
