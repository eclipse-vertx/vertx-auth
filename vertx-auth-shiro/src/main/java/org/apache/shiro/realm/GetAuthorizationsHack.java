package org.apache.shiro.realm;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.mgt.AuthorizingSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;

public class GetAuthorizationsHack {

  public static Set<Authorization> getAuthorizations(SecurityManager securityManager, Subject subject) {
    Objects.requireNonNull(securityManager);

    Set<Authorization> result = Collections.emptySet();
    if (subject.getPrincipals()!=null) {
      if (securityManager instanceof AuthorizingSecurityManager) {
        AuthorizingSecurityManager authorizingSecurityManager = (AuthorizingSecurityManager) securityManager;
        if (authorizingSecurityManager.getAuthorizer() instanceof ModularRealmAuthorizer) {
          result= new HashSet<>();
          ModularRealmAuthorizer modularRealmAuthorizer = (ModularRealmAuthorizer) authorizingSecurityManager.getAuthorizer();
          for (Realm realm: modularRealmAuthorizer.getRealms()) {
            if (realm instanceof AuthorizingRealm) {
              AuthorizingRealm authorizingRealm = (AuthorizingRealm) realm;
              AuthorizationInfo authorizationInfo = authorizingRealm.getAuthorizationInfo(subject.getPrincipals());
              if (authorizationInfo!=null) {
                if (authorizationInfo.getRoles()!=null) {
                  for (String role: authorizationInfo.getRoles()) {
                    result.add(RoleBasedAuthorization.create(role));
                  }
                }
                if (authorizationInfo.getStringPermissions()!=null) {
                  for (String permission: authorizationInfo.getStringPermissions()) {
                    result.add(WildcardPermissionBasedAuthorization.create(permission));
                  }
                }
                if (authorizationInfo.getObjectPermissions()!=null) {
                  for (Permission permission: authorizationInfo.getObjectPermissions()) {
                    String stringPermission = permission.toString();
                    stringPermission= stringPermission.replace("[", "").replace("]", "");
                    result.add(WildcardPermissionBasedAuthorization.create(stringPermission));
                  }
                }
              }
            }
          }

        }
      }
    }
    return result;
  }

}
