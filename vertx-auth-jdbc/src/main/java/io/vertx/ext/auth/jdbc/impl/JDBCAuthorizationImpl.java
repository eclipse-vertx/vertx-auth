package io.vertx.ext.auth.jdbc.impl;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jdbc.JDBCAuthorization;
import io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

@Deprecated
public class JDBCAuthorizationImpl implements JDBCAuthorization {

  /**
   * The default key representing the username in the principal
   */
  private final static String DEFAULT_USERNAME_KEY = "username";

  private final String providerId;
  private final JDBCAuthorizationOptions options;
  private final JDBCClient client;
  private final String usernameKey;

  public JDBCAuthorizationImpl(String providerId, JDBCClient client, JDBCAuthorizationOptions options) {
    this.providerId = Objects.requireNonNull(providerId);
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
    this.usernameKey = DEFAULT_USERNAME_KEY;
  }

  @Override
  public String getId() {
    return providerId;
  }

  private void getRoles(SQLConnection sqlConnection, JsonArray params, Handler<AsyncResult<Set<Authorization>>> resultHandler) {
    if (options.getRolesQuery() != null) {
      sqlConnection.queryWithParams(options.getRolesQuery(), params, queryResponse -> {
        if (queryResponse.succeeded()) {
          Set<Authorization> authorizations = new HashSet<>();
          ResultSet resultSet = queryResponse.result();
          for (JsonArray result : resultSet.getResults()) {
            String role = result.getString(0);
            authorizations.add(RoleBasedAuthorization.create(role));
          }
          resultHandler.handle(Future.succeededFuture(authorizations));
        } else {
          resultHandler.handle(Future.failedFuture(queryResponse.cause()));
        }
      });
    } else {
      resultHandler.handle(Future.succeededFuture(Collections.emptySet()));
    }
  }

  private void getPermissions(SQLConnection sqlConnection, JsonArray params, Handler<AsyncResult<Set<Authorization>>> resultHandler) {
    if (options.getPermissionsQuery() != null) {
      sqlConnection.queryWithParams(options.getPermissionsQuery(), params, queryResponse -> {
        if (queryResponse.succeeded()) {
          Set<Authorization> authorizations = new HashSet<>();
          ResultSet resultSet = queryResponse.result();
          for (JsonArray result : resultSet.getResults()) {
            String permission = result.getString(0);
            authorizations.add(PermissionBasedAuthorization.create(permission));
          }
          resultHandler.handle(Future.succeededFuture(authorizations));
        } else {
          resultHandler.handle(Future.failedFuture(queryResponse.cause()));
        }
      });
    } else {
      resultHandler.handle(Future.succeededFuture(Collections.emptySet()));
    }
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizations(user)
      .onComplete(handler);
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    final Promise<Void> promise = Promise.promise();

    client.getConnection(connectionResponse -> {
      if (connectionResponse.succeeded()) {
        String username = user.principal().getString(usernameKey);
        if (username != null) {
          JsonArray params = new JsonArray().add(username);
          SQLConnection connection = connectionResponse.result();
          getRoles(connection, params, roleResponse -> {
            if (roleResponse.succeeded()) {
              Set<Authorization> authorizations = new HashSet<>(roleResponse.result());
              getPermissions(connection, params, permissionResponse -> {
                if (permissionResponse.succeeded()) {
                  authorizations.addAll(permissionResponse.result());
                  user.authorizations().add(getId(), authorizations);
                  promise.complete();
                } else {
                  promise.fail(permissionResponse.cause());
                }
                connection.close();
              });
            } else {
              promise.fail(roleResponse.cause());
              connection.close();
            }
          });
        } else {
          promise.fail("Couldn't get the username");
          connectionResponse.result().close();
        }
      } else {
        promise.fail(connectionResponse.cause());
      }
    });

    return promise.future();
  }
}
