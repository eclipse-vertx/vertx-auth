package io.vertx.ext.auth.htpasswd;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.htpasswd.impl.HtpasswdAuthImpl;

/**
 * Created by nevenr on 11/03/2017.
 */
public interface HtpasswdAuth extends AuthProvider {

  String HTPASSWD_FILE = "htpasswd";

  static HtpasswdAuth create(Vertx vertx) {
    return new HtpasswdAuthImpl(vertx, HTPASSWD_FILE);
  }

  static HtpasswdAuth create(Vertx vertx, String htpasswdfile) {
    return new HtpasswdAuthImpl(vertx, htpasswdfile);
  }

}
