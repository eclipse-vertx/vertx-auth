package io.vertx.ext.auth;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;

/**
 * Interface representing any kind of authorization such as: - Role based
 * authorization - Permission based authorization - Logical authorization (AND,
 * OR, NOT) - Time based authorization (ie: allow access the last 5 days of the
 * month, from 8am till 10am, etc.) - Context based authorization (ie: allow
 * access if the ip address is 'xxx.xxx.xxx.xxx') - Custom based authorization
 * (ie: based on a script or hard-coded code specific to an application) - etc.
 * 
 * The following implementations are provided out of the box: -
 * {@link AndAuthorization} - {@link NotAuthorization} - {@link OrAuthorization}
 * - {@link PermissionBasedAuthorization} - {@link RoleBasedAuthorization} -
 * {@link WildcardPermissionBasedAuthorization}
 * 
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface Authorization {

  /**
   * this methods verifies whether or not the authorization match the specified
   * context.
   * 
   * @param context
   * @return
   */
  @GenIgnore
  boolean match(AuthorizationContext context);

  /**
   * 
   * this method verifies whether or not the authorization implies the specified
   * authorization. Note that it doesn't always mean an exact match. For instance,
   * in the case of a {@link WildcardPermissionBasedAuthorization}, this method
   * may return true even if the permissions are different =>
   * WildcardPermissionBasedAuthorization.create('*').implies(WildcardPermissionBasedAuthorization.create('anypermission'))
   * would return true
   * 
   * @param authorization
   * @return
   */
  @GenIgnore
  boolean verify(Authorization authorization);

}
