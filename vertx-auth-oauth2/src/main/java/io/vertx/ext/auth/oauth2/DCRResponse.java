package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

@DataObject
@JsonGen(publicConverter = false)
public class DCRResponse {
  private String id;
  private String clientId;
  private boolean enabled;
  private String clientAuthenticationType;
  private String secret;
  private String registrationAccessToken;

  public DCRResponse(JsonObject json) {
    DCRResponseConverter.fromJson(json, this);
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    DCRResponseConverter.toJson(this, json);
    return json;
  }

  public String getId() {
    return id;
  }

  public String getClientId() {
    return clientId;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public String getClientAuthenticationType() {
    return clientAuthenticationType;
  }

  public String getSecret() {
    return secret;
  }

  public String getRegistrationAccessToken() {
    return registrationAccessToken;
  }
}