package io.vertx.ext.auth;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.RoleBasedAuthorizationImpl;

/**
 * Represents a role. Note that this role can optionally be assigned to a
 * specific resource
 * 
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface RoleBasedAuthorization extends Authorization {

  static RoleBasedAuthorization create(String role) {
    return new RoleBasedAuthorizationImpl(role);
  }

  /**
   * returns the role
   * 
   * @return
   */
  String getRole();

  /**
   * returns an optional resource that the role is assigned-on
   * 
   * @return
   */
  String getResource();

  /**
   * sets an optional resource that the role is assigned-on
   * 
   * @return
   */
  @Fluent
  RoleBasedAuthorization setResource(String resource);

}
