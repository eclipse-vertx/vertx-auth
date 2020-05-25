package io.vertx.ext.auth.jdbc;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true, publicConverter = false)
public class JDBCAuthInfo {

  private String password;
  private String username;

  public JDBCAuthInfo() {
  }

  public JDBCAuthInfo(JsonObject jsonObject) {
    JDBCAuthInfoConverter.fromJson(jsonObject, this);
  }

  public String getPassword() {
    return password;
  }

  public String getUsername() {
    return username;
  }

  public JDBCAuthInfo setPassword(String password) {
    this.password = password;
    return this;
  }

  public JDBCAuthInfo setUsername(String username) {
    this.username = username;
    return this;
  }

  public JsonObject toJson() { 
    JsonObject result = new JsonObject();
    JDBCAuthInfoConverter.toJson(this,
    result); return result; 
  }

}
