package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true)
public class RelayParty {
  private String id;
  private String name;
  private String icon;

  public RelayParty() {
  }

  public RelayParty(JsonObject json) {
    RelayPartyConverter.fromJson(json, this);
  }

  public RelayParty(RelayParty other) {
    this.id = other.id;
    this.name = other.name;
    this.icon = other.icon;
  }

  public String getId() {
    return id;
  }

  public RelayParty setId(String id) {
    this.id = id;
    return this;
  }

  public String getName() {
    return name;
  }

  public RelayParty setName(String name) {
    this.name = name;
    return this;
  }

  public String getIcon() {
    return icon;
  }

  public RelayParty setIcon(String icon) {
    this.icon = icon;
    return this;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    RelayPartyConverter.toJson(this, json);
    return json;
  }
}
