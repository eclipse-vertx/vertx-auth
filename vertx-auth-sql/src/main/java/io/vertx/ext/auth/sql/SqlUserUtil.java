package io.vertx.ext.auth.sql;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.ext.auth.sql.impl.SqlUserUtilImpl;
import io.vertx.sqlclient.SqlClient;

import java.util.Map;

/**
 * Utility to create users/roles/permissions. This is a helper class and not intended to be a full user
 * management utility. While the standard authentication and authorization interfaces will require usually
 * read only access to the database, in order to use this API a full read/write access must be granted.
 */
@VertxGen
public interface SqlUserUtil {

  /**
   * Create an instance of the user helper.
   * @param client the client with write rights to the database.
   * @return the instance
   */
  static SqlUserUtil create(SqlClient client) {
    return new SqlUserUtilImpl(client);
  }

  /**
   * Create an instance of the user helper with custom queries.
   * @param client the client with write rights to the database.
   * @return the instance
   */
  static SqlUserUtil create(SqlClient client, String insertUserSQL, String insertUserRoleSQL, String insertRolePermissionSQL) {
    return new SqlUserUtilImpl(client, insertUserSQL, insertUserRoleSQL, insertRolePermissionSQL);
  }

  /**
   * Insert a user into a database.
   *
   * @param username
   *          the username to be set
   * @param password
   *          the passsword in clear text, will be adapted following the definitions of the defined strategy
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  SqlUserUtil createUser(String username, String password, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createUser(String, String, Handler).
   */
  default Future<Void> createUser(String username, String password) {
    Promise<Void> promise = Promise.promise();
    createUser(username, password, promise);
    return promise.future();
  }

  /**
   * Insert a user into a database.
   *
   * @param username
   *          the username to be set
   * @param hash
   *          the password hash, as result of {@link io.vertx.ext.auth.HashingStrategy#hash(String, Map, String, String)}
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  SqlUserUtil createHashedUser(String username, String hash, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createHashedUser(String, String, Handler).
   */
  default Future<Void> createHashedUser(String username, String hash) {
    Promise<Void> promise = Promise.promise();
    createHashedUser(username, hash, promise);
    return promise.future();
  }

  /**
   * Insert a user role into a database.
   *
   * @param username
   *          the username to be set
   * @param role
   *          a to be set
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  SqlUserUtil createUserRole(String username, String role, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createUserRole(String, String, Handler).
   */
  default Future<Void> createUserRole(String user, String role) {
    Promise<Void> promise = Promise.promise();
    createUserRole(user, role, promise);
    return promise.future();
  }

  /**
   * Insert a role permission into a database.
   *
   * @param role
   *          a to be set
   * @param permission
   *          the permission to be set
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  SqlUserUtil createRolePermission(String role, String permission, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createRolePermission(String, String, Handler).
   */
  default Future<Void> createRolePermission(String role, String permission) {
    Promise<Void> promise = Promise.promise();
    createRolePermission(role, permission, promise);
    return promise.future();
  }
}
