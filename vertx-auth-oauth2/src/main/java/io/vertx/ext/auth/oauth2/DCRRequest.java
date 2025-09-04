package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

@DataObject
@JsonGen(publicConverter = false)
public class DCRRequest {
  private String clientId;
  private String registrationAccessToken;

  public DCRRequest(JsonObject json) {
    DCRRequestConverter.fromJson(json, this);
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    DCRRequestConverter.toJson(this, json);
    return json;
  }
  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getRegistrationAccessToken() {
    return registrationAccessToken;
  }
  public void setRegistrationAccessToken(String registrationAccessToken) {
    this.registrationAccessToken = registrationAccessToken;
  }
}