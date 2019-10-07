package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;

@DataObject(generateConverter = true)
public class RelayParty {
  private String name;
  private String id;
  private String icon;
}
