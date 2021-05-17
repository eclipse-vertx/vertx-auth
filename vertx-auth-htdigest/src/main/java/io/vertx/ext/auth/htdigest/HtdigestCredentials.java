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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Credentials specific to the {@link HtdigestAuth} authentication provider
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@DataObject(generateConverter = true, publicConverter = false)
public class HtdigestCredentials extends UsernamePasswordCredentials implements Credentials {

  private static final Pattern PARSER = Pattern.compile("(\\w+)=[\"]?([^\"]*)[\"]?$");
  private static final Pattern SPLITTER = Pattern.compile(",(?=(?:[^\"]|\"[^\"]*\")*$)");

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

  public HtdigestCredentials() {
    super();
  }

  public HtdigestCredentials(String username, String password) {
    super(username, password);
  }

  public HtdigestCredentials(JsonObject jsonObject) {
    super(jsonObject);
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

  @Override
  public HtdigestCredentials setUsername(String username) {
    super.setUsername(username);
    return this;
  }

  @Override
  public HtdigestCredentials setPassword(String password) {
    super.setPassword(password);
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    final String username = getUsername();

    if (username == null || username.length() == 0) {
      throw new CredentialValidationException("username cannot be null or empty");
    }

    if (realm == null) {
      throw new CredentialValidationException("realm cannot be null");
    }

    if (arg != null && (Boolean) arg) {
      // client validation
      if (getPassword() == null) {
        throw new CredentialValidationException("password cannot be null");
      }
      if (nonce == null) {
        throw new CredentialValidationException("nonce cannot be null");
      }
      if (opaque == null) {
        throw new CredentialValidationException("opaque cannot be null");
      }
      if (method == null) {
        throw new CredentialValidationException("method cannot be null");
      }
      if (uri == null) {
        throw new CredentialValidationException("uri cannot be null");
      }

      if (qop != null) {
        String[] qops = qop.split(",");
        boolean found = false;
        for (String q : qops) {
          if ("auth".equals(q)) {
            qop = "auth";
            found = true;
            break;
          }
        }
        if (!found) {
          throw new CredentialValidationException(qop + " qop is not supported");
        }
        if (nc == null) {
          throw new CredentialValidationException("nc cannot be null");
        }
        if (cnonce == null) {
          throw new CredentialValidationException("cnonce cannot be null");
        }
      }

    } else {
      // server validation
      if (response == null) {
        throw new CredentialValidationException("response cannot be null");
      }
    }

    // all remaining fields have dependencies between themselves, which means
    // the authentication process will take care of it's validation
  }

  public JsonObject toJson() {
    JsonObject result = super.toJson();
    HtdigestCredentialsConverter.toJson(this, result);
    return result;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  @Override
  public HtdigestCredentials applyHttpChallenge(String challenge, HttpMethod method, String uri, Integer nc, String cnonce) throws CredentialValidationException {
    if (challenge == null) {
      throw new IllegalArgumentException("Digest auth requires a challenge");
    }

    int spc = challenge.indexOf(' ');

    if (!"Digest".equalsIgnoreCase(challenge.substring(0, spc))) {
      throw new IllegalArgumentException("Only 'Digest' auth-scheme is supported");
    }

    // parse the challenge
    // Split the parameters by comma.
    String[] tokens = SPLITTER.split(challenge.substring(spc + 1));
    // Parse parameters.
    int i = 0;
    int len = tokens.length;

    while (i < len) {
      // Strip quotes and whitespace.
      Matcher m = PARSER.matcher(tokens[i]);
      if (m.find()) {
        switch (m.group(1)) {
          case "nonce":
            nonce = m.group(2);
            break;
          case "opaque":
            opaque = m.group(2);
            break;
          case "qop":
            qop = m.group(2);
            break;
          case "algorithm":
            algorithm = m.group(2);
            break;
          case "realm":
            realm = m.group(2);
            break;
        }
      }

      ++i;
    }

    // apply the remaining properties
    this.method = method != null ? method.name() : null;
    this.uri = uri;
    this.nc = nc != null ? nc.toString() : null;
    this.cnonce = cnonce;

    // validate
    checkValid(true);

    return this;
  }

  @Override
  public String toHttpAuthorization() {
    // start assembling the response

    final MessageDigest MD5;

    try {
      MD5 = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    byte[] ha1 = MD5.digest(String.join(":", getUsername(), realm, getPassword()).getBytes(StandardCharsets.UTF_8));

    if ("MD5-sess".equals(algorithm)) {
      ha1 = MD5.digest(
        Buffer.buffer()
          .appendBytes(ha1)
          .appendByte((byte) ':')
          .appendString(nonce)
          .appendByte((byte) ':')
          .appendString(cnonce)
          .getBytes());
    }

    byte[] ha2 = MD5.digest(String.join(":", method, uri).getBytes(StandardCharsets.UTF_8));

    // Generate response hash
    Buffer response = Buffer.buffer()
      .appendString(bytesToHex(ha1))
      .appendByte((byte) ':')
      .appendString(nonce);

    if (qop != null) {
      response
        .appendByte((byte) ':')
        .appendString(nc)
        .appendByte((byte) ':')
        .appendString(cnonce)
        .appendByte((byte) ':')
        .appendString(qop);
    }

    response
      .appendByte((byte) ':')
      .appendString(bytesToHex(ha2));

    Buffer header = Buffer.buffer("Digest ");

    header
      .appendString("username=\"").appendString(getUsername().replaceAll("\"", "\\\""))
      .appendString("\", realm=\"").appendString(realm)
      .appendString("\", nonce=\"").appendString(nonce)
      .appendString("\", uri=\"").appendString(uri);

    if (qop != null) {
      header
        .appendString("\", qop=").appendString(qop)
        .appendString(", nc=").appendString(nc)
        .appendString(", cnonce=\"").appendString(cnonce.replaceAll("\"", "\\\""));
    }

    header
      .appendString("\", response=\"").appendString(bytesToHex(MD5.digest(response.getBytes())))
      .appendString("\", opaque=\"").appendString(opaque)
      .appendString("\"");

    return header.toString();
  }

  private final static char[] hexArray = "0123456789abcdef".toCharArray();

  private static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}
