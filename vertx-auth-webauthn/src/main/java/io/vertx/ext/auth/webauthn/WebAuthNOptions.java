package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@DataObject(generateConverter = true)
public class WebAuthNOptions {

  private String realm;
  private String realmDisplayName;
  private String realmIcon;
  private String origin;
  private List<String> transports = Arrays.asList("usb", "nfc", "ble", "internal");

  public int getChallengeLength() {
    return challengeLength;
  }

  public void setChallengeLength(int challengeLength) {
    this.challengeLength = challengeLength;
  }

  private int challengeLength = 32;

  public WebAuthNOptions() {}
  public WebAuthNOptions(JsonObject json) {
  }

  public String getRealm() {
    return realm;
  }

  public WebAuthNOptions setRealm(String realm) {
    this.realm = realm;
    return this;
  }

  public String getOrigin() {
    return origin;
  }

  public WebAuthNOptions setOrigin(String origin) {
    this.origin = origin;
    return this;
  }

  public String getRealmDisplayName() {
    return realmDisplayName;
  }

  public WebAuthNOptions setRealmDisplayName(String realmDisplayName) {
    this.realmDisplayName = realmDisplayName;
    return this;
  }

  public String getRealmIcon() {
    return realmIcon;
  }

  public WebAuthNOptions setRealmIcon(String realmIcon) {
    this.realmIcon = realmIcon;
    return this;
  }

  public List<String> getTransports() {
    return transports;
  }

  public WebAuthNOptions setTransports(List<String> transports) {
    this.transports = transports;
    return this;
  }

  public WebAuthNOptions addTransport(String transport) {
    if (transports == null) {
      transports = new ArrayList<>();
    }

    this.transports.add(transport);
    return this;
  }
}
