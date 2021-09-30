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

package io.vertx.ext.auth.webauthn.impl;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import io.netty.buffer.ByteBufInputStream;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.DecodeException;

import java.io.*;
import java.util.*;

public final class CBOR {

  private static final Base64.Encoder B64ENC = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64DEC = Base64.getUrlDecoder();
  private static final CBORFactory FACTORY = new CBORFactory();

  public static JsonParser cborParser(String base64) {
    return cborParser(B64DEC.decode(base64));
  }

  public static JsonParser cborParser(byte[] data) {
    try {
      return FACTORY.createParser(data);
    } catch (IOException e) {
      throw new DecodeException("Failed to decode:" + e.getMessage(), e);
    }
  }

  public static JsonParser cborParser(Buffer buf) {
    try {
      return FACTORY.createParser((InputStream) new ByteBufInputStream(buf.getByteBuf()));
    } catch (IOException e) {
      throw new DecodeException("Failed to decode:" + e.getMessage(), e);
    }
  }

  public static <T> T parse(JsonParser parser) throws DecodeException {
    try {
      if (parser.currentToken() == null) {
        parser.nextToken();
      }
      return (T) parseAny(parser);
    } catch (IOException e) {
      throw new DecodeException(e.getMessage(), e);
    }
  }

  private static @Nullable Object parseAny(JsonParser parser) throws IOException, DecodeException {
    switch (parser.getCurrentTokenId()) {
      case JsonTokenId.ID_START_OBJECT:
        return parseObject(parser);
      case JsonTokenId.ID_START_ARRAY:
        return parseArray(parser);
      case JsonTokenId.ID_EMBEDDED_OBJECT:
        return B64ENC.encodeToString(parser.getBinaryValue(Base64Variants.MODIFIED_FOR_URL));
      case JsonTokenId.ID_STRING:
        return parser.getText();
      case JsonTokenId.ID_NUMBER_FLOAT:
      case JsonTokenId.ID_NUMBER_INT:
        return parser.getNumberValue();
      case JsonTokenId.ID_TRUE:
        return Boolean.TRUE;
      case JsonTokenId.ID_FALSE:
        return Boolean.FALSE;
      case JsonTokenId.ID_NULL:
        return null;
      default:
        throw new DecodeException("Unexpected token"/*, parser.getCurrentLocation()*/);
    }
  }

  private static Map<String, Object> parseObject(JsonParser parser) throws IOException {
    String key1 = parser.nextFieldName();
    if (key1 == null) {
      return new LinkedHashMap<>(2);
    }
    parser.nextToken();
    Object value1 = parseAny(parser);
    String key2 = parser.nextFieldName();
    if (key2 == null) {
      LinkedHashMap<String, Object> obj = new LinkedHashMap<>(2);
      obj.put(key1, value1);
      return obj;
    }
    parser.nextToken();
    Object value2 = parseAny(parser);
    String key = parser.nextFieldName();
    if (key == null) {
      LinkedHashMap<String, Object> obj = new LinkedHashMap<>(2);
      obj.put(key1, value1);
      obj.put(key2, value2);
      return obj;
    }
    // General case
    LinkedHashMap<String, Object> obj = new LinkedHashMap<>();
    obj.put(key1, value1);
    obj.put(key2, value2);
    do {
      parser.nextToken();
      Object value = parseAny(parser);
      obj.put(key, value);
      key = parser.nextFieldName();
    } while (key != null);
    return obj;
  }

  private static List<Object> parseArray(JsonParser parser) throws IOException {
    List<Object> array = new ArrayList<>();
    while (true) {
      parser.nextToken();
      int tokenId = parser.getCurrentTokenId();
      if (tokenId == JsonTokenId.ID_FIELD_NAME) {
        throw new UnsupportedOperationException();
      } else if (tokenId == JsonTokenId.ID_END_ARRAY) {
        return array;
      }
      Object value = parseAny(parser);
      array.add(value);
    }
  }
}
