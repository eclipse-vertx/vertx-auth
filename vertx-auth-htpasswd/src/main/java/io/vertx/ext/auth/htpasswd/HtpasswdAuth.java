package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.htpasswd.impl.HtpasswdAuthImpl;

/**
 * An extension of AuthProvider which is using htpasswd file as store
 *
 * @author Neven Radovanović
 */
@VertxGen
public interface HtpasswdAuth extends AuthProvider {

  static HtpasswdAuth create(Vertx vertx) {
    return new HtpasswdAuthImpl(vertx, new HtpasswdAuthOptions());
  }

  static HtpasswdAuth create(Vertx vertx, HtpasswdAuthOptions htpasswdAuthOptions) {
    return new HtpasswdAuthImpl(vertx, htpasswdAuthOptions);
  }

}
