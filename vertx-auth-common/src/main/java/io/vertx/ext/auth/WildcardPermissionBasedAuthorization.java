package io.vertx.ext.auth;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.WildcardPermissionBasedAuthorizationImpl;

/**
 * Represents a wildcard permission (ie: 'manage:order:*' '*:orders', '*', etc.)
 * Note that it can optionally be assigned to a specific resource
 * 
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface WildcardPermissionBasedAuthorization extends Authorization {

  static WildcardPermissionBasedAuthorization create(String permission) {
    return new WildcardPermissionBasedAuthorizationImpl(permission);
  }

  /**
   * return the value of the wildcard permission
   * 
   * @return
   */
  String getPermission();

  /**
   * returns an optional resource that the permission is assigned-on
   * 
   * @return
   */
  String getResource();

  /**
   * sets an optional resource that the permission is assigned-on
   * 
   * @return
   */
  @Fluent
  WildcardPermissionBasedAuthorization setResource(String resource);

}
