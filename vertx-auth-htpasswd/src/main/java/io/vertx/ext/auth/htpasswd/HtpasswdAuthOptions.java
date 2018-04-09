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

  private String htpasswdFile;
  private boolean enabledPlainText;

  public HtpasswdAuthOptions() {
    htpasswdFile = ".htpasswd";
    enabledPlainText = false;
  }

  public HtpasswdAuthOptions(JsonObject json) {
    this();
    HtpasswdAuthOptionsConverter.fromJson(json, this);
  }

  public HtpasswdAuthOptions(HtpasswdAuthOptions that) {
    this();
    this.usersAuthorizedForEverything = that.usersAuthorizedForEverything;
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

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    HtpasswdAuthOptionsConverter.toJson(this, json);
    return json;
  }
}
