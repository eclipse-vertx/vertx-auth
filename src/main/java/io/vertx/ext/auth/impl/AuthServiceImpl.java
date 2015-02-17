package io.vertx.ext.auth.impl;

import io.vertx.core.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.spi.AuthProvider;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceImpl implements AuthService, Handler<Long> {

  private final Vertx vertx;
  private final AuthProvider provider;
  private final Map<String, LoginSession> loginSessions = new ConcurrentHashMap<>();
  private final long reaperPeriod;
  private long timerID;
  private boolean closed;

  public AuthServiceImpl(Vertx vertx, JsonObject config, AuthProvider provider, long reaperPeriod) {
    this.vertx = vertx;
    this.provider = provider;
    this.reaperPeriod = reaperPeriod;
    provider.init(config);
    setTimer();
  }

  public AuthServiceImpl(Vertx vertx, JsonObject config, String className, long reaperPeriod) {
    this.vertx = vertx;
    this.reaperPeriod = reaperPeriod;
    ClassLoader cl = getClassLoader();
    try {
      Class<?> clazz = cl.loadClass(className);
      this.provider = (AuthProvider)clazz.newInstance();
      provider.init(config);
    } catch (Exception e) {
      throw new VertxException(e);
    }
    setTimer();
  }

  private String createLoginSession(long timeout, Object principal) {
    String id = UUID.randomUUID().toString();
    loginSessions.put(id, new LoginSession(timeout, principal));
    return id;
  }

  @Override
  public void login(JsonObject credentials, Handler<AsyncResult<String>> resultHandler) {
    loginWithTimeout(credentials, DEFAULT_LOGIN_TIMEOUT, resultHandler);
  }

  @Override
  public void loginWithTimeout(JsonObject credentials, long timeout, Handler<AsyncResult<String>> resultHandler) {
    provider.login(credentials, res -> {
      if (res.succeeded()) {
        Object principal = res.result();
        if (principal != null) {
          String loginSessionID = createLoginSession(timeout, principal);
          resultHandler.handle(Future.succeededFuture(loginSessionID));
        } else {
          resultHandler.handle(Future.failedFuture("null principal"));
        }
      } else {
        resultHandler.handle(Future.failedFuture(res.cause()));
      }
    });
  }

  @Override
  public void logout(String loginID, Handler<AsyncResult<Void>> resultHandler) {
    LoginSession session = loginSessions.remove(loginID);
    resultHandler.handle(session == null ? Future.failedFuture("not logged in") : Future.succeededFuture());
  }

  @Override
  public void refreshLoginSession(String loginID, Handler<AsyncResult<Void>> resultHandler) {
    LoginSession session = loginSessions.get(loginID);
    if (session != null) {
      session.touch();
    }
    resultHandler.handle(session == null ? Future.failedFuture("not logged in") : Future.succeededFuture());
  }

  @Override
  public void hasRole(String loginID, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    LoginSession session = loginSessions.get(loginID);
    if (session != null) {
      doHasRole(session, role, resultHandler);
    } else {
      resultHandler.handle(Future.failedFuture("not logged in"));
    }
  }

  @Override
  public void hasPermission(String loginID, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    LoginSession session = loginSessions.get(loginID);
    if (session != null) {
      doHasPermission(session, permission, resultHandler);
    } else {
      resultHandler.handle(Future.failedFuture("not logged in"));
    }
  }

  @Override
  public void hasRoles(String loginID, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    LoginSession session = loginSessions.get(loginID);
    if (session != null) {
      Handler<AsyncResult<Boolean>> wrapped = wrappedHandler(roles.size(), resultHandler);
      for (String role: roles) {
        doHasRole(session, role, wrapped);
      }
    } else {
      resultHandler.handle(Future.failedFuture("not logged in"));
    }
  }

  @Override
  public void hasPermissions(String loginID, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    LoginSession session = loginSessions.get(loginID);
    if (session != null) {
      Handler<AsyncResult<Boolean>> wrapped = wrappedHandler(permissions.size(), resultHandler);
      for (String permission: permissions) {
        doHasPermission(session, permission, wrapped);
      }
    } else {
      resultHandler.handle(Future.failedFuture("not logged in"));
    }
  }

  private void doHasRole(LoginSession session, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    if (session.hasRole(role)) {
      resultHandler.handle(Future.succeededFuture(true));
    } else if (session.hasNotRole(role)) {
      resultHandler.handle(Future.succeededFuture(false));
    } else {
      // Don't know - need to check with provider
      provider.hasRole(session.principal(), role, res -> {
        if (res.succeeded()) {
          boolean hasRole = res.result();
          if (hasRole) {
            session.addRole(role);
          } else {
            session.addNotRole(role);
          }
          resultHandler.handle(Future.succeededFuture(hasRole));
        } else {
          resultHandler.handle(Future.failedFuture(res.cause()));
        }
      });
    }
  }

  private void doHasPermission(LoginSession session, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    if (session.hasPermission(permission)) {
      resultHandler.handle(Future.succeededFuture(true));
    } else if (session.hasNotPermission(permission)) {
      resultHandler.handle(Future.succeededFuture(false));
    } else {
      // Don't know - need to check with provider
      provider.hasPermission(session.principal(), permission, res -> {
        if (res.succeeded()) {
          boolean hasPermission = res.result();
          if (hasPermission) {
            session.addPermission(permission);
          } else {
            session.addNotPermission(permission);
          }
          resultHandler.handle(Future.succeededFuture(hasPermission));
        } else {
          resultHandler.handle(Future.failedFuture(res.cause()));
        }
      });
    }
  }


  private Handler<AsyncResult<Boolean>> wrappedHandler(int num, Handler<AsyncResult<Boolean>> resultHandler) {
    AtomicInteger cnt = new AtomicInteger();
    AtomicBoolean sent = new AtomicBoolean();
    return res -> {
      if (res.succeeded()) {
        boolean hasRole = res.result();
        int count = cnt.incrementAndGet();
        if (!hasRole) {
          if (sent.compareAndSet(false, true)) {
            resultHandler.handle(Future.succeededFuture(false));
          }
        } else {
          if (count == num) {
            if (sent.compareAndSet(false, true)) {
              resultHandler.handle(Future.succeededFuture(true));
            }
          }
        }
      } else {
        if (sent.compareAndSet(false, true)) {
          resultHandler.handle(Future.failedFuture(res.cause()));
        }
      }
    };
  }

  private ClassLoader getClassLoader() {
    ClassLoader tccl = Thread.currentThread().getContextClassLoader();
    return tccl == null ? getClass().getClassLoader(): tccl;
  }

  @Override
  public synchronized void handle(Long tid) {
    long now = System.currentTimeMillis();
    Iterator<Map.Entry<String, LoginSession>> iter = loginSessions.entrySet().iterator();
    while (iter.hasNext()) {
      Map.Entry<String, LoginSession> entry = iter.next();
      LoginSession session = entry.getValue();
      if (now - session.lastAccessed() > session.timeout()) {
        iter.remove();
      }
    }
    if (!closed) {
      setTimer();
    }
  }

  private void setTimer() {
    if (reaperPeriod != 0) {
      timerID = vertx.setTimer(reaperPeriod, this);
    }
  }

  @Override
  public synchronized void start() {
    closed = false;
    setTimer();
  }

  @Override
  public synchronized void stop() {
    closed = true;
    loginSessions.clear();
    if (timerID != -1) {
      vertx.cancelTimer(timerID);
    }

  }
}
