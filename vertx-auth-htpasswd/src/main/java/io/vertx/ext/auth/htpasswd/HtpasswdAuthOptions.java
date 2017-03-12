package io.vertx.ext.auth.htpasswd;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthOptions;
import io.vertx.ext.auth.AuthProvider;

/**
 * Created by nevenr on 12/03/2017.
 */
public class HtpasswdAuthOptions implements AuthOptions {

  private String htpasswdFile;
  private boolean enabledPlainTextPwd;

  public HtpasswdAuthOptions() {

    htpasswdFile = "htpasswd";

    String os = System.getProperty("os.name").toLowerCase();
    enabledPlainTextPwd = os.startsWith("windows") || os.startsWith("netware");

  }

  public HtpasswdAuthOptions(HtpasswdAuthOptions that) {
    this.htpasswdFile = that.htpasswdFile;
    this.enabledPlainTextPwd = that.enabledPlainTextPwd;
  }

  public HtpasswdAuthOptions enablePlainTextAndDisableCryptPwd() {
    enabledPlainTextPwd = true;
    return this;

  }

  public HtpasswdAuthOptions enableCryptAndDisablePlainTextPwd() {
    enabledPlainTextPwd = false;
    return this;
  }

  public String getHtpasswdFile() {
    return htpasswdFile;
  }

  public void setHtpasswdFile(String htpasswdFile) {
    this.htpasswdFile = htpasswdFile;
  }

  public boolean isEnabledPlainTextPwd() {
    return enabledPlainTextPwd;
  }

  public boolean isEnabledCryptPwd() {
    return !enabledPlainTextPwd;
  }

  @Override
  public AuthOptions clone() {
    return new HtpasswdAuthOptions(this);
  }

  @Override
  public AuthProvider createProvider(Vertx vertx) {
    return HtpasswdAuth.create(vertx,this);
  }
}
