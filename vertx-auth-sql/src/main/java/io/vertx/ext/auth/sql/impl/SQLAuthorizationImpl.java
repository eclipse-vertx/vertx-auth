package io.vertx.ext.auth.sql.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.sql.SQLAuthorization;
import io.vertx.ext.auth.sql.SQLAuthorizationOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class SQLAuthorizationImpl implements SQLAuthorization {

  private final SQLAuthorizationOptions options;
  private final SqlClient client;

  public SQLAuthorizationImpl(SqlClient client, SQLAuthorizationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
  }

  @Override
  public String getId() {
    return "sql-client";
  }

  private void getRoles(String username, Handler<AsyncResult<Set<Authorization>>> resultHandler) {
    if (options.getRolesQuery() != null) {
      client.preparedQuery(options.getRolesQuery(), Tuple.of(username), preparedQuery -> {
        if (preparedQuery.succeeded()) {
          RowSet<Row> rows = preparedQuery.result();
          Set<Authorization> authorizations = new HashSet<>();
          for (Row row : rows) {
            String role = row.getString(0);
            authorizations.add(RoleBasedAuthorization.create(role));
          }
          resultHandler.handle(Future.succeededFuture(authorizations));
        } else {
          resultHandler.handle(Future.failedFuture(preparedQuery.cause()));
        }
      });
    } else {
      resultHandler.handle(Future.succeededFuture(Collections.emptySet()));
    }
  }

  private void getPermissions(String username, Handler<AsyncResult<Set<Authorization>>> resultHandler) {
    if (options.getPermissionsQuery() != null) {
      client.preparedQuery(options.getPermissionsQuery(), Tuple.of(username), preparedQuery -> {
        if (preparedQuery.succeeded()) {
          RowSet<Row> rows = preparedQuery.result();
          Set<Authorization> authorizations = new HashSet<>();
          for (Row row : rows) {
            String permission = row.getString(0);
            authorizations.add(PermissionBasedAuthorization.create(permission));
          }
          resultHandler.handle(Future.succeededFuture(authorizations));
        } else {
          resultHandler.handle(Future.failedFuture(preparedQuery.cause()));
        }
      });
    } else {
      resultHandler.handle(Future.succeededFuture(Collections.emptySet()));
    }
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> resultHandler) {
    String username = user.principal().getString("username");
    if (username != null) {
      getRoles(username, roleResponse -> {
        if (roleResponse.succeeded()) {
          Set<Authorization> authorizations = new HashSet<>(roleResponse.result());
          getPermissions(username, permissionResponse -> {
            if (permissionResponse.succeeded()) {
              authorizations.addAll(permissionResponse.result());
              resultHandler.handle(Future.succeededFuture(authorizations));
            } else {
              resultHandler.handle(Future.failedFuture(permissionResponse.cause()));
            }
          });
        } else {
          resultHandler.handle(Future.failedFuture(roleResponse.cause()));
        }
      });
    } else {
      resultHandler.handle(Future.failedFuture("Couldn't get the username from the principal"));
    }
  }
}
