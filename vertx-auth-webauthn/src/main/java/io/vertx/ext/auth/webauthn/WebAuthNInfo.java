/*
 * Copyright 2019 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true)
public class WebAuthNInfo {

  private String challenge;
  private JsonObject webauthn;
  private String username;

  public WebAuthNInfo() {}

  public WebAuthNInfo(JsonObject json) {
    WebAuthNInfoConverter.fromJson(json, this);
  }

  public String getChallenge() {
    return challenge;
  }

  public WebAuthNInfo setChallenge(String challenge) {
    this.challenge = challenge;
    return this;
  }

  public JsonObject getWebauthn() {
    return webauthn;
  }

  public WebAuthNInfo setWebauthn(JsonObject webauthn) {
    this.webauthn = webauthn;
    return this;
  }

  public String getUsername() {
    return username;
  }

  public WebAuthNInfo setUsername(String username) {
    this.username = username;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    WebAuthNInfoConverter.toJson(this, json);
    return json;
  }
}
