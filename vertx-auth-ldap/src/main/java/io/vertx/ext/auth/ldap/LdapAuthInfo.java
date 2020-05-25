package io.vertx.ext.auth.ldap;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true, publicConverter = false)
public class LdapAuthInfo {

  private String password;
  private String username;

  public LdapAuthInfo() {
  }

  public LdapAuthInfo(JsonObject jsonObject) {
    LdapAuthInfoConverter.fromJson(jsonObject, this);
  }

  public String getPassword() {
    return password;
  }

  public String getUsername() {
    return username;
  }

  public LdapAuthInfo setPassword(String password) {
    this.password = password;
    return this;
  }

  public LdapAuthInfo setUsername(String username) {
    this.username = username;
    return this;
  }

  public JsonObject toJson() { 
    JsonObject result = new JsonObject();
    LdapAuthInfoConverter.toJson(this,
    result); return result; 
  }

}
