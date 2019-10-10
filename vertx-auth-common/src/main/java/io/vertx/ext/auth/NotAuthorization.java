package io.vertx.ext.auth;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.NotAuthorizationImpl;

/**
 * Allows to perform a logical 'not' of the specified authorization
 * 
 * @author <a href="mailto:stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 * 
 */
@VertxGen
public interface NotAuthorization extends Authorization {

  static NotAuthorization create(Authorization authorization) {
    return new NotAuthorizationImpl(authorization);
  }

  Authorization getAuthorization();

}
