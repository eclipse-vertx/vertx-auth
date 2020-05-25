package io.vertx.ext.auth.jwt;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true, publicConverter = false)
public class JWTAuthInfo {

  private String jwt;

  public JWTAuthInfo() {
  }

  public JWTAuthInfo(JsonObject jsonObject) {
    JWTAuthInfoConverter.fromJson(jsonObject, this);
  }

  public String getJwt() {
    return jwt;
  }

  public JWTAuthInfo setJwt(String jwt) {
    this.jwt = jwt;
    return this;
  }

  public JsonObject toJson() { 
    JsonObject result = new JsonObject();
    JWTAuthInfoConverter.toJson(this,
    result); return result; 
  }

}
