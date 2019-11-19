package io.vertx.ext.auth.jdbc.impl;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.PermissionBasedAuthorization;
import io.vertx.ext.auth.RoleBasedAuthorization;
import io.vertx.ext.auth.User;
<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthorizationProviderImpl.java
import io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions;
import io.vertx.ext.auth.jdbc.JDBCAuthorizationProvider;
=======
import io.vertx.ext.auth.jdbc.JDBCAuthorization;
import io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions;
>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthorizationImpl.java
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

public class JDBCAuthorizationImpl implements JDBCAuthorization {
  
  /**
   * The default key representing the username in the principal
   */
  private final static String DEFAULT_USERNAME_KEY = "username";
  
  private String providerId;
  private JDBCClient client;
  private JDBCAuthorizationOptions options;
  private String usernameKey;
  
<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthorizationProviderImpl.java
  public JDBCAuthorizationProviderImpl(String providerId, JDBCClient client, JDBCAuthorizationOptions options) {
    this.providerId = Objects.requireNonNull(providerId);
=======
  public JDBCAuthorizationImpl(JDBCClient client) {
    this.client = Objects.requireNonNull(client);
    this.roleQuery = DEFAULT_ROLES_QUERY;
    this.permissionsQuery = DEFAULT_PERMISSIONS_QUERY;
    this.usernameKey = DEFAULT_USERNAME_KEY;
  }

  public JDBCAuthorizationImpl(JDBCAuthorizationOptions options) {
>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthorizationImpl.java
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
    this.usernameKey = DEFAULT_USERNAME_KEY;
  }

  @Override
  public String getId() {
    return providerId;
  }

  private void getRoles(SQLConnection sqlConnection, JsonArray params,
      Handler<AsyncResult<Set<Authorization>>> resultHandler) {
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

  private void getPermissions(SQLConnection sqlConnection, JsonArray params,
      Handler<AsyncResult<Set<Authorization>>> resultHandler) {
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
  public void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> resultHandler) {
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
                  resultHandler.handle(Future.succeededFuture(authorizations));
                } else {
                  resultHandler.handle(Future.failedFuture(permissionResponse.cause()));
                }
                connection.close();
              });
            } else {
              resultHandler.handle(Future.failedFuture(roleResponse.cause()));
              connection.close();
            }
          });
        } else {
          resultHandler.handle(Future.failedFuture("Couldn't get the username"));
          connectionResponse.result().close();
        }
      } else {
        resultHandler.handle(Future.failedFuture(connectionResponse.cause()));
      }
    });
  }

<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthorizationProviderImpl.java
=======
  @Override
  public JDBCAuthorization setRolesQuery(String rolesQuery) {
    this.roleQuery = rolesQuery;
    return this;
  }

  @Override
  public JDBCAuthorization setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
    return this;
  }
  
>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthorizationImpl.java
}
