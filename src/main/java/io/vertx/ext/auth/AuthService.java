package io.vertx.ext.auth;

import io.vertx.codegen.annotations.*;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthServiceImpl;
import io.vertx.ext.auth.spi.AuthProvider;
import io.vertx.serviceproxy.ProxyHelper;

import java.util.Set;

/**
 * Vert.x authentication and authorisation service.
 * <p>
 * Handles authentication and role/permission based authorisation.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
@ProxyGen
public interface AuthService {

  /**
   * How long in ms, by default, a login will remain valid for before being expired
   */
  public static final long DEFAULT_LOGIN_TIMEOUT = 30 * 60 * 1000;

  /**
   * How long, in ms, to check for expired logins and remove them.
   */
  public static final long DEFAULT_REAPER_PERIOD = 5 * 1000;

  /**
   * Create an auth service instance using the specified auth provider instance.
   *
   * @param vertx  the Vert.x instance
   * @param provider  the auth provider
   * @param config  the configuration to pass to the provider
   * @return the auth service
   */
  @GenIgnore
  static AuthService create(Vertx vertx, AuthProvider provider, JsonObject config) {
    return new AuthServiceImpl(vertx, config, provider);
  }

  /**
   * Create an auth service instance using the specified auth provider class name.
   *
   * @param vertx  the Vert.x instance
   * @param className  the fully qualified class name of the auth provider implementation class
   * @param config  the configuration to pass to the provider
   * @return the auth service
   */
  static AuthService createFromClassName(Vertx vertx, String className, JsonObject config) {
    return new AuthServiceImpl(vertx, config, className);
  }

  /**
   * Create a proxy to an auth service that is deployed somwehere on the event bus.
   *
   * @param vertx  the vert.x instance
   * @param address  the address on the event bus where the auth service is listening
   * @return  the proxy
   */
  static AuthService createEventBusProxy(Vertx vertx, String address) {
    return ProxyHelper.createProxy(AuthService.class, vertx, address);
  }

  /**
   * Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   * provider is expecting. The default login ID timeout will be used.
   *
   * @param credentials  the credentials
   * @param resultHandler will be passed a failed result if login failed or will be passed a succeeded result containing
   *                      the login ID (a string) if login was successful.
   */
  @Fluent
  AuthService login(JsonObject credentials, Handler<AsyncResult<String>> resultHandler);

  /**
   * Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   * provider is expecting. The specified login ID timeout will be used.
   *
   * @param credentials  the credentials
   * @param timeout  the login timeout to use, in ms
   * @param resultHandler will be passed a failed result if login failed or will be passed a succeeded result containing
   *                      the login ID (a string) if login was successful.
   */
  @Fluent
  AuthService loginWithTimeout(JsonObject credentials, long timeout, Handler<AsyncResult<String>> resultHandler);

  /**
   * Logout the user
   *
   * @param loginID  the login ID as provided by {@link #login}.
   * @param resultHandler  will be called with success or failure
   */
  @Fluent
  AuthService logout(String loginID, Handler<AsyncResult<Void>> resultHandler);

  /**
   * Refresh an existing login ID so it doesn't expire
   *
   * @param loginID  the login ID as provided by {@link #login}.
   * @param resultHandler  will be called with success or failure
   */
  @Fluent
  AuthService refreshLoginSession(String loginID, Handler<AsyncResult<Void>> resultHandler);

  /**
   * Does the user have the specified role?
   *
   * @param loginID  the login ID as provided by {@link #login}.
   * @param role  the role
   * @param resultHandler  will be called with the result - true if has role, false if not
   */
  @Fluent
  AuthService hasRole(String loginID, String role, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Does the user have the specified roles?
   *
   * @param loginID  the login ID as provided by {@link #login}.
   * @param roles  the set of roles
   * @param resultHandler  will be called with the result - true if has roles, false if not
   */
  @Fluent
  AuthService hasRoles(String loginID, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Does the user have the specified permission?
   *
   * @param loginID  the login ID as provided by {@link #login}.
   * @param permission  the permission
   * @param resultHandler  will be called with the result - true if has permission, false if not
   */
  @Fluent
  AuthService hasPermission(String loginID, String permission, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Does the user have the specified permissions?
   *
   * @param loginID  the login ID as provided by {@link #login}.
   * @param permissions  the set of permissions
   * @param resultHandler  will be called with the result - true if has permissions, false if not
   */
  @Fluent
  AuthService hasPermissions(String loginID, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Set the reaper period - how often to check for expired logins, in ms.
   *
   * @param reaperPeriod  the reaper period, in ms
   */
  @Fluent
  AuthService setReaperPeriod(long reaperPeriod);

  /**
   * Start the service
   */
  @ProxyIgnore
  void start();

  /**
   * Stop the service
   */
  @ProxyIgnore
  void stop();

}
