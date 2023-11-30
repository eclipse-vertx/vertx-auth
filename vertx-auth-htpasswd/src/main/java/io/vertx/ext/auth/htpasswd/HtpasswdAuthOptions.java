/*
 * Copyright 2014 Red Hat, Inc.
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
package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

/**
 * Options configuring htpasswd authentication.
 *
 * @author Neven Radovanović
 */
@DataObject
@JsonGen(publicConverter = false)
public class HtpasswdAuthOptions {

  private String htpasswdFile;
  private boolean plainTextEnabled;

  public HtpasswdAuthOptions() {
    htpasswdFile = ".htpasswd";
    plainTextEnabled = false;
  }

  public HtpasswdAuthOptions(JsonObject json) {
    this();
    HtpasswdAuthOptionsConverter.fromJson(json, this);
  }

  public HtpasswdAuthOptions(HtpasswdAuthOptions that) {
    this();
    this.htpasswdFile = that.htpasswdFile;
    this.plainTextEnabled = that.plainTextEnabled;
  }

  public HtpasswdAuthOptions setPlainTextEnabled(boolean plainTextEnabled) {
    this.plainTextEnabled = plainTextEnabled;
    return this;
  }

  public boolean isPlainTextEnabled() {
    return plainTextEnabled;
  }

  public String getHtpasswdFile() {
    return htpasswdFile;
  }

  public HtpasswdAuthOptions setHtpasswdFile(String htpasswdFile) {
    this.htpasswdFile = htpasswdFile;
    return this;
  }
}
