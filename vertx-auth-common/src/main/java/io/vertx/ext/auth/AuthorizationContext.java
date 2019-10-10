package io.vertx.ext.auth;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.MultiMap;

/**
 * The AuthorizationContext contains properties that can be used to match
 * authorizations.
 * 
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface AuthorizationContext {

  /**
   * Get the authenticated user
   * 
   * @return the user
   */
  User user();

  /**
   * @return a Multimap containing variable names and values that can be resolved
   *         at runtime by {@link Authorization}Authorizations
   */
  MultiMap variables();

}
