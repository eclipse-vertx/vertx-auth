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

package io.vertx.ext.auth.impl.cose;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.jose.JWK;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * CBOR Object Signing and Encryption (COSE)
 * <p>
 * Concise Binary Object Representation (CBOR) is a data format designed
 * for small code size and small message size.  There is a need for the
 * ability to have basic security services defined for this data format.
 * This document defines the CBOR Object Signing and Encryption (COSE)
 * protocol.  This specification describes how to create and process
 * signatures, message authentication codes, and encryption using CBOR
 * for serialization.  This specification additionally describes how to
 * represent cryptographic keys using CBOR.
 * <p>
 * This class allows converting a COSE KEY to a JOSE KEY for ease of use.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public final class CWK {

  private static class NV {
    private final String name;
    private final Map<String, String> values;

    private NV(String name, String... pairs) {
      this.name = name;
      if (pairs == null || pairs.length == 0) {
        this.values = Collections.emptyMap();
      } else {
        if (pairs.length % 2 != 0) {
          throw new IllegalArgumentException("pairs must have even length");
        }
        Map<String, String> tmp = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
          tmp.put(pairs[i], pairs[i + 1]);
        }
        this.values = Collections.unmodifiableMap(tmp);
      }
    }
  }

  // main COSE labels
  // defined here: https://tools.ietf.org/html/rfc8152#section-7.1
  private static final Map<String, NV> COSE_LABELS = Collections.unmodifiableMap(new HashMap<String, NV>() {{
    put("1",
      new NV("kty", "1", "OKP", "2", "EC", "3", "RSA"));
    put("2",
      new NV("kid"));
    put("3",
      new NV("alg", "-7", "ES256", "-8", "EdDSA", "-35", "ES384", "-36", "ES512", "-37", "PS256", "-38", "PS384", "-39", "PS512", "-47", "ES256K", "-257", "RS256", "-258", "RS384", "-259", "RS512", "-65535", "RS1"));
    put("4",
      new NV("key_ops"));
    put("5",
      new NV("base_iv"));
  }});

  // ECDSA key parameters
  // defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
  private static final Map<String, NV> EC_KEY_PARAMS = Collections.unmodifiableMap(new HashMap<String, NV>() {{
    put("-1",
      new NV("crv", "1", "P-256", "2", "P-384", "3", "P-521", "8", "secp256k1")
    );
    put("-2",
      new NV("x"));
    put("-3",
      new NV("y"));
    put("-4",
      new NV("d"));
  }});

  // EdDSA key parameters
  // defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
  private static final Map<String, NV> OKP_KEY_PARAMS = Collections.unmodifiableMap(new HashMap<String, NV>() {{
    put("-1",
      new NV("crv", "4", "X25519", "5", "X448", "6", "Ed25519", "7", "Ed448")
    );
    put("-2",
      new NV("x"));
    put("-3",
      new NV("y"));
    put("-4",
      new NV("d"));
  }});

  // RSA key parameters
  // defined here: https://tools.ietf.org/html/rfc8230#section-4
  private static final Map<String, NV> RSA_KEY_PARAMS = Collections.unmodifiableMap(new HashMap<String, NV>() {{
    put("-1",
      new NV("n"));
    put("-2",
      new NV("e"));
    put("-3",
      new NV("d"));
    put("-4",
      new NV("p"));
    put("-5",
      new NV("q"));
    put("-6",
      new NV("dp"));
    put("-7",
      new NV("dq"));
    put("-8",
      new NV("qi"));
    put("-9",
      new NV("other"));
    put("-10",
      new NV("r_i"));
    put("-11",
      new NV("d_i"));
    put("-12",
      new NV("t_i"));
  }});

  private static final Map<String, Map<String, NV>> KEY_PARAMS = Collections.unmodifiableMap(new HashMap<String, Map<String, NV>>() {{
    put("OKP", OKP_KEY_PARAMS);
    put("EC", EC_KEY_PARAMS);
    put("RSA", RSA_KEY_PARAMS);
  }});

  public static JWK toJWK(Iterable<Map.Entry<String, Object>> coseMap) {
    JsonObject retKey = new JsonObject();
    Map<String, String> extraMap = new HashMap<>();

    // parse main COSE labels
    for (Map.Entry<String, Object> kv : coseMap) {
      String key = kv.getKey();
      String value = kv.getValue().toString();

      if (!COSE_LABELS.containsKey(key)) {
        extraMap.put(key, value);
        continue;
      }

      String name = COSE_LABELS.get(key).name;
      if (COSE_LABELS.get(key).values.containsKey(value)) {
        value = COSE_LABELS.get(key).values.get(value);
      }

      retKey.put(name, value);
    }

    Map<String, NV> keyParams = KEY_PARAMS.get(retKey.getString("kty"));

    // parse key-specific parameters
    for (Map.Entry<String, String> kv : extraMap.entrySet()) {
      String key = kv.getKey();
      String value = kv.getValue();

      if (!keyParams.containsKey(key)) {
        throw new RuntimeException("unknown COSE key label: " + retKey.getString("kty") + " " + key);
      }

      String name = keyParams.get(key).name;

      if (keyParams.get(key).values.containsKey(value)) {
        value = keyParams.get(key).values.get(value);
      }

      retKey.put(name, value);
    }

    return new JWK(retKey);
  }
}
