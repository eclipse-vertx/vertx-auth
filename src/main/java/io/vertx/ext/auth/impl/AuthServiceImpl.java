package io.vertx.ext.auth.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.PropertiesRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;


/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceImpl implements AuthService {

  protected final Vertx vertx;
  protected final Realm realm;
  protected final DefaultSecurityManager securityManager;


  public AuthServiceImpl(Vertx vertx, JsonObject config) {
    this.vertx = vertx;
    PropertiesRealm realm = new PropertiesRealm();
    realm.setResourcePath("classpath:test-auth.properties");
    realm.init();
    this.realm = realm;
    this.securityManager = new DefaultSecurityManager(realm);
  }

  @Override
  public void login(JsonObject credentials, Handler<AsyncResult<Void>> resultHandler) {

    vertx.executeBlocking((Future<Void> fut) -> {
      SubjectContext subjectContext = new DefaultSubjectContext();
      Subject subject = securityManager.createSubject(subjectContext);
      String username = credentials.getString("username");
      String password = credentials.getString("password");
      AuthenticationToken token = new UsernamePasswordToken(username, password);
      try {
        subject.login(token);
        fut.complete();
      } catch( AuthenticationException ae ) {
        fut.fail(ae.getMessage());
      }
    }, resultHandler);

  }

  @Override
  public void hasRole(String subject, Handler<AsyncResult<Boolean>> resultHandler) {

  }

  @Override
  public void hasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {

  }

  public void start() {

  }

  @Override
  public void stop() {

  }

}
