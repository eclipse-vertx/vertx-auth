package io.vertx.ext.auth.htpasswd;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthOptions;
import io.vertx.ext.auth.AuthProvider;

/**
 * Options configuring htpasswd authentication.
 *
 * @author Neven Radovanović
 */
public class HtpasswdAuthOptions implements AuthOptions {

  private String htpasswdFile;
  private boolean enabledPlainText;

  public HtpasswdAuthOptions() {
    htpasswdFile = ".htpasswd";
    enabledPlainText = false;
  }

  public HtpasswdAuthOptions(HtpasswdAuthOptions that) {
    this.htpasswdFile = that.htpasswdFile;
    this.enabledPlainText = that.enabledPlainText;
  }

  public HtpasswdAuthOptions setEnablePlainText(boolean enabledPlainText) {
    this.enabledPlainText = enabledPlainText;
    return this;
  }

  public boolean isEnablePlainText() {
    return enabledPlainText;
  }

  public String getHtpasswdFile() {
    return htpasswdFile;
  }

  public HtpasswdAuthOptions setHtpasswdFile(String htpasswdFile) {
    this.htpasswdFile = htpasswdFile;
    return this;
  }

  @Override
  public AuthOptions clone() {
    return new HtpasswdAuthOptions(this);
  }

  @Override
  public AuthProvider createProvider(Vertx vertx) {
    return HtpasswdAuth.create(vertx, this);
  }
}
