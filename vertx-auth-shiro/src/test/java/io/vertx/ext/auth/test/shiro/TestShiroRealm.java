package io.vertx.ext.auth.test.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

public class TestShiroRealm implements Realm {

  @Override
  public String getName() {
    return getClass().getName();
  }

  @Override
  public boolean supports(AuthenticationToken token) {
    return true;
  }

  @Override
  public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

    return new AuthenticationInfo() {
      @Override
      public PrincipalCollection getPrincipals() {
        return new SimplePrincipalCollection(token.getPrincipal(), getClass().getName());
      }

      @Override
      public Object getCredentials() {
        return token.getCredentials();
      }
    };
  }

}