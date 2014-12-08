package io.vertx.ext.auth.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthRealm;
import io.vertx.ext.auth.AuthRealmType;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.impl.realms.LDAPAuthRealm;
import io.vertx.ext.auth.impl.realms.PropertiesAuthRealm;

import java.util.Set;


/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceImpl implements AuthService {

  protected final Vertx vertx;
  protected final AuthRealm realm;
  protected final JsonObject config;

  public AuthServiceImpl(Vertx vertx, JsonObject config) {
    this.vertx = vertx;
    this.config = config;
    String realmClassName = config.getString(AUTH_REALM_CLASS_NAME_FIELD);
    if (realmClassName != null) {
      try {
        Class clazz = getClassLoader().loadClass(realmClassName);
        this.realm = (AuthRealm)clazz.newInstance();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    } else {
      String realmType = config.getString(AUTH_REALM_TYPE_FIELD);
      AuthRealmType type;
      if (realmType == null) {
        type = AuthRealmType.PROPERTIES; // Default
      } else {
        try {
          type = AuthRealmType.valueOf(realmType);
        } catch (IllegalArgumentException e) {
          throw new IllegalArgumentException(AUTH_REALM_TYPE_FIELD + ": " + realmType);
        }
      }
      switch (type) {
        case PROPERTIES:
          this.realm = new PropertiesAuthRealm();
          break;
        case JDBC:
          // TODO
          throw new UnsupportedOperationException();
        case LDAP:
          this.realm = new LDAPAuthRealm();
          break;
        default:
          throw new IllegalArgumentException(AUTH_REALM_TYPE_FIELD + ": " + realmType);
      }
    }
    realm.init(config);
  }


  public AuthServiceImpl(Vertx vertx, AuthRealm authRealm, JsonObject config) {
    this.vertx = vertx;
    this.config = config;
    this.realm = authRealm;
    realm.init(config);
  }

  @Override
  public void login(JsonObject credentials, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      boolean ok = realm.login(credentials);
      fut.complete(ok);
    }, resultHandler);
  }

  @Override
  public void hasRole(String principal, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      boolean hasRole = realm.hasRole(principal, role);
      fut.complete(hasRole);
    }, resultHandler);
  }

  @Override
  public void hasPermission(String principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      boolean hasRole = realm.hasPermission(principal, permission);
      fut.complete(hasRole);
    }, resultHandler);
  }

  @Override
  public void hasRoles(String principal, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      for (String role: roles) {
        if (!realm.hasRole(principal, role)) {
          fut.complete(false);
          return;
        }
      }
      fut.complete(true);
    }, resultHandler);
  }

  @Override
  public void hasPermissions(String principal, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      for (String permission : permissions) {
        if (!realm.hasPermission(principal, permission)) {
          fut.complete(false);
          return;
        }
      }
      fut.complete(true);
    }, resultHandler);
  }

  public void start() {
  }

  @Override
  public void stop() {
  }

  private ClassLoader getClassLoader() {
    ClassLoader tccl = Thread.currentThread().getContextClassLoader();
    return tccl == null ? getClass().getClassLoader(): tccl;
  }


}
