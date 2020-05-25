package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true, publicConverter = false)
public class HtpasswdAuthInfo {

  private String password;
  private String username;

  public HtpasswdAuthInfo() {
  }

  public HtpasswdAuthInfo(JsonObject jsonObject) {
    HtpasswdAuthInfoConverter.fromJson(jsonObject, this);
  }

  public String getPassword() {
    return password;
  }

  public String getUsername() {
    return username;
  }

  public HtpasswdAuthInfo setPassword(String password) {
    this.password = password;
    return this;
  }

  public HtpasswdAuthInfo setUsername(String username) {
    this.username = username;
    return this;
  }

  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    HtpasswdAuthInfoConverter.toJson(this, result);
    return result;
  }

}
