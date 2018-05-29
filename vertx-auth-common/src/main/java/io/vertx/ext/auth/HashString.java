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
package io.vertx.ext.auth;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class to encode/decore hashed strings to be stored on a persistent storage.
 *
 * This follows as close as possible the <a href="https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md">phc sf spec</a>.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public final class HashString {

  private String id;
  private Map<String, String> params;
  private String salt;
  private String hash;

  public HashString(String id, Map<String, String> params, String salt) {
    this.id = id;
    this.params = params;
    this.salt = salt;
  }

  public HashString(String encoded) {
    String[] parts;

    if (encoded.length() > 1 && encoded.charAt(0) != '$') {
      // this is not a hash encoded in the common format, attempt to normalize
      encoded = encoded.replaceAll("\\{", "\\$\\{");
      encoded = encoded.replaceAll("\\}", "\\}\\$");
      if (encoded.length() > 1 && encoded.charAt(0) != '$') {
        encoded = "$$" + encoded;
      }
    }

    parts = encoded.split("\\$");

    if (parts.length < 2) {
      throw new IllegalStateException("Not enough segments: " + encoded);
    }

    switch (parts.length) {
      case 2:
        id = parts[1];
      case 3:
        id = parts[1];
        hash = parts[2];
        break;
      case 4:
        id = parts[1];
        salt = parts[2];
        hash = parts[3];
        break;
      case 5:
      // fallback if there are more segments (just ignore)
      default:
        id = parts[1];
        params = new HashMap<>();
        for (String kv : parts[2].split(",")) {
          int eq = kv.indexOf('=');
          if (eq > 0) {
            params.put(kv.substring(0, eq), kv.substring(eq + 1));
          }
        }
        salt = parts[3];
        hash = parts[4];
        break;
    }
  }

  public String id() {
    return id;
  }

  public String param(String param) {
    if (params == null) {
      return null;
    }

    return params.get(param);
  }

  public Map<String, String> params() {
    return params;
  }

  public String salt() {
    return salt;
  }

  public String hash() {
    return hash;
  }

  public static String encode(HashingAlgorithm algorithm, Map<String, String> params, String salt, String hash) {
    StringBuilder sb = new StringBuilder();

    if (algorithm.needsSeparator()) {
      sb.append('$');
    }

    sb.append(algorithm.id());

    if (params != null) {
      if (algorithm.needsSeparator()) {
        sb.append('$');
      }
      boolean notEmpty = false;
      for (String key : algorithm.params()) {
        String value = params.get(key);
        if (value != null) {
          if (notEmpty) {
            sb.append(',');
          }
          sb.append(key);
          sb.append('=');
          sb.append(params.get(key));
          notEmpty = true;
        }
      }
    }
    if (salt != null) {
      if (algorithm.needsSeparator()) {
        sb.append('$');
      }
      sb.append(salt);
    }
    if (hash != null) {
      if (algorithm.needsSeparator()) {
        sb.append('$');
      }
      sb.append(hash);
    }

    return sb.toString();
  }

  @Override
  public String toString() {
    return "id=" + id() + ",params=" + params() + ",salt=" + salt() + ",hash=" + hash();
  }
}
