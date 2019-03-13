package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@DataObject
public class WebAuthNOptions {

  private String realm;
  private List<String> transports = Arrays.asList("usb", "nfc", "ble");

  public String getRealm() {
    return realm;
  }

  public WebAuthNOptions setRealm(String realm) {
    this.realm = realm;
    return this;
  }

  public WebAuthNOptions() {}
  public WebAuthNOptions(JsonObject json) {}

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
