/********************************************************************************
 * Copyright (c) 2029 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.htdigest;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;

/**
 * Credentials specific to the {@link HtdigestAuth} authentication provider
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@DataObject(generateConverter = true, publicConverter = false)
public class HtdigestCredentials implements Credentials {

  private String algorithm;
  private String cnonce;
  private String method;
  private String nc;
  private String nonce;
  private String opaque;
  private String qop;
  private String realm;
  private String response;
  private String uri;
  private String username;

  public HtdigestCredentials() {
  }

  public HtdigestCredentials(JsonObject jsonObject) {
    HtdigestCredentialsConverter.fromJson(jsonObject, this);
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public String getCnonce() {
    return cnonce;
  }

  public String getMethod() {
    return method;
  }

  public String getNc() {
    return nc;
  }

  public String getNonce() {
    return nonce;
  }

  public String getOpaque() {
    return opaque;
  }

  public String getQop() {
    return qop;
  }

  public String getRealm() {
    return realm;
  }

  public String getResponse() {
    return response;
  }

  public String getUri() {
    return uri;
  }

  public String getUsername() {
    return username;
  }

  public HtdigestCredentials setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  public HtdigestCredentials setCnonce(String cnonce) {
    this.cnonce = cnonce;
    return this;
  }

  public HtdigestCredentials setMethod(String method) {
    this.method = method;
    return this;
  }

  public HtdigestCredentials setNc(String nc) {
    this.nc = nc;
    return this;
  }

  public HtdigestCredentials setNonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  public HtdigestCredentials setOpaque(String opaque) {
    this.opaque = opaque;
    return this;
  }

  public HtdigestCredentials setQop(String qop) {
    this.qop = qop;
    return this;
  }

  public HtdigestCredentials setRealm(String realm) {
    this.realm = realm;
    return this;
  }

  public HtdigestCredentials setResponse(String response) {
    this.response = response;
    return this;
  }

  public HtdigestCredentials setUri(String uri) {
    this.uri = uri;
    return this;
  }

  public HtdigestCredentials setUsername(String username) {
    this.username = username;
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (username == null || username.length() == 0) {
      throw new CredentialValidationException("username cannot be null or empty");
    }

    if (realm == null) {
      throw new CredentialValidationException("realm cannot be null");
    }

    if (response == null) {
      throw new CredentialValidationException("response cannot be null");
    }

    // all remaining fields have dependencies between themselves, which means
    // the authentication process will take care of it's validation
  }

  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    HtdigestCredentialsConverter.toJson(this, result);
    return result;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
