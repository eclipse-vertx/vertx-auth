package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthOptions;
import io.vertx.ext.auth.AuthProvider;

/**
 * Options configuring htpasswd authentication.
 *
 * @author Neven Radovanović
 */
@DataObject(generateConverter = true)
public class HtpasswdAuthOptions implements AuthOptions {

  private boolean usersAuthorizedForEverything;
  private String htpasswdFile;
  private boolean enabledPlainTextPwd;

  public HtpasswdAuthOptions() {
    htpasswdFile = "htpasswd";
    String os = System.getProperty("os.name").toLowerCase();
    enabledPlainTextPwd = os.startsWith("windows") || os.startsWith("netware");
    usersAuthorizedForEverything = false;
  }

  public HtpasswdAuthOptions(JsonObject json) {
    this();
    HtpasswdAuthOptionsConverter.fromJson(json, this);
  }

  public HtpasswdAuthOptions(HtpasswdAuthOptions that) {
    this();
    this.usersAuthorizedForEverything = that.usersAuthorizedForEverything;
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

  public HtpasswdAuthOptions setHtpasswdFile(String htpasswdFile) {
    this.htpasswdFile = htpasswdFile;
    return this;
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
    return HtpasswdAuth.create(vertx, this);
  }

  public boolean areUsersAuthorizedForEverything() {
    return usersAuthorizedForEverything;
  }

  public HtpasswdAuthOptions setUsersAuthorizedForEverything(boolean usersAuthorizedForEverything) {
    this.usersAuthorizedForEverything = usersAuthorizedForEverything;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    HtpasswdAuthOptionsConverter.toJson(this, json);
    return json;
  }
}
