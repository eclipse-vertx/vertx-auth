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
import io.vertx.codegen.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

/**
 * Data object representing a Relying party (your server)
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class RelyingParty {

  /**
   * The id (or domain name of your server)
   */
  private String id;

  /**
   * A user friendly name for your server
   */
  private String name;

  /**
   * A URL location for an icon
   */
  @Deprecated
  private String icon;

  public RelyingParty() {
  }

  public RelyingParty(JsonObject json) {
    RelyingPartyConverter.fromJson(json, this);
  }

  public RelyingParty(RelyingParty other) {
    this.id = other.id;
    this.name = other.name;
    this.icon = other.icon;
  }

  public String getId() {
    return id;
  }

  public RelyingParty setId(String id) {
    this.id = id;
    return this;
  }

  public String getName() {
    return name;
  }

  public RelyingParty setName(String name) {
    this.name = name;
    return this;
  }

  @Deprecated
  public String getIcon() {
    return icon;
  }

  @Deprecated
  public RelyingParty setIcon(String icon) {
    this.icon = icon;
    return this;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    RelyingPartyConverter.toJson(this, json);
    return json;
  }
}
