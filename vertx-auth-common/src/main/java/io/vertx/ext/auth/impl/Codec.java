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
package io.vertx.ext.auth.impl;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A collection of simple codecs to avoid code duplication across modules.
 * <p>
 * This helper provies codecs for Base16, Base32 and Base64.
 *
 * @author Paulo Lopes
 */
public final class Codec {

  private Codec() {
  }

  private static final byte[] BASE16 = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
  private static final int[] BASE16_LOOKUP =
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF
    };

  private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
  private static final int[] BASE32_LOOKUP =
    {0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();

  private static final Base64.Encoder BASE64 = Base64.getEncoder();
  private static final Base64.Encoder BASE64_NOPADDING = Base64.getEncoder().withoutPadding();
  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  private static final Base64.Encoder BASE64MIME = Base64.getMimeEncoder();
  private static final Base64.Decoder BASE64MIME_DECODER = Base64.getMimeDecoder();

  public static String base16Encode(byte[] bytes) {
    byte[] base16 = new byte[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xFF;
      base16[i * 2] = BASE16[v >>> 4];
      base16[i * 2 + 1] = BASE16[v & 0x0F];
    }
    return new String(base16, StandardCharsets.ISO_8859_1);
  }

  public static byte[] base16Decode(String base16) {
    int lookup;
    byte[] bytes = new byte[base16.length() / 2];

    for (int i = 0; i < base16.length(); i += 2) {
      lookup = base16.charAt(i) - '0';
      /* chars outside the lookup table */
      if (lookup < 0 || lookup >= BASE16_LOOKUP.length) {
        throw new IllegalArgumentException("Invalid char: " + (base16.charAt(i)));
      }
      int high = BASE16_LOOKUP[lookup];
      /* If this digit is not in the table, fail */
      if (high == 0xFF) {
        throw new IllegalArgumentException("Invalid char: " + (base16.charAt(i)));
      }

      lookup = base16.charAt(i + 1) - '0';
      /* chars outside the lookup table */
      if (lookup < 0 || lookup >= BASE16_LOOKUP.length) {
        throw new IllegalArgumentException("Invalid char: " + (base16.charAt(i + 1)));
      }
      int low = BASE16_LOOKUP[lookup];
      /* If this digit is not in the table, fail */
      if (low == 0xFF) {
        throw new IllegalArgumentException("Invalid char: " + (base16.charAt(i + 1)));
      }
      bytes[i / 2] = (byte) ((high << 4) + low);
    }
    return bytes;
  }

  public static String base32Encode(byte[] bytes) {
    int i = 0, index = 0, digit;
    int currByte, nextByte;
    StringBuilder base32 = new StringBuilder(((bytes.length + 7) * 8 / 5));

    while (i < bytes.length) {
      currByte = (bytes[i] >= 0) ? bytes[i] : (bytes[i] + 256);

      /* Is the current digit going to span a byte boundary? */
      if (index > 3) {
        if ((i + 1) < bytes.length) {
          nextByte = (bytes[i + 1] >= 0)
            ? bytes[i + 1] : (bytes[i + 1] + 256);
        } else {
          nextByte = 0;
        }

        digit = currByte & (0xFF >> index);
        index = (index + 5) % 8;
        digit <<= index;
        digit |= nextByte >> (8 - index);
        i++;
      } else {
        digit = (currByte >> (8 - (index + 5))) & 0x1F;
        index = (index + 5) % 8;
        if (index == 0)
          i++;
      }
      base32.append(BASE32[digit]);
    }

    return base32.toString();
  }

  static public byte[] base32Decode(final String base32) {
    int i, index, lookup, offset, digit;
    byte[] bytes = new byte[base32.length() * 5 / 8];

    for (i = 0, index = 0, offset = 0; i < base32.length(); i++) {
      lookup = base32.charAt(i) - '0';

      /* Fail if chars outside the lookup table */
      if (lookup < 0 || lookup >= BASE32_LOOKUP.length) {
        throw new IllegalArgumentException("Invalid char: " + (base32.charAt(i)));
      }

      digit = BASE32_LOOKUP[lookup];

      /* If this digit is not in the table, fail */
      if (digit == 0xFF) {
        throw new IllegalArgumentException("Invalid char: " + (base32.charAt(i)));
      }

      if (index <= 3) {
        index = (index + 5) % 8;
        if (index == 0) {
          bytes[offset] |= digit;
          offset++;
          if (offset >= bytes.length)
            break;
        } else {
          bytes[offset] |= digit << (8 - index);
        }
      } else {
        index = (index + 5) % 8;
        bytes[offset] |= (digit >>> index);
        offset++;

        if (offset >= bytes.length) {
          break;
        }
        bytes[offset] |= digit << (8 - index);
      }
    }
    return bytes;
  }

  public static String base64UrlEncode(byte[] bytes) {
    return BASE64URL.encodeToString(bytes);
  }

  public static byte[] base64UrlDecode(String base64) {
    return BASE64URL_DECODER.decode(base64);
  }

  public static byte[] base64UrlDecode(byte[] base64) {
    return BASE64URL_DECODER.decode(base64);
  }

  public static String base64Encode(byte[] bytes) {
    return BASE64.encodeToString(bytes);
  }

  public static String base64EncodeWithoutPadding(byte[] bytes) {
    return BASE64_NOPADDING.encodeToString(bytes);
  }

  public static byte[] base64Decode(String base64) {
    return BASE64_DECODER.decode(base64);
  }

  public static byte[] base64Decode(byte[] base64) {
    return BASE64_DECODER.decode(base64);
  }

  public static String base64MimeEncode(byte[] bytes) {
    return BASE64MIME.encodeToString(bytes);
  }

  public static byte[] base64MimeDecode(String base64) {
    return BASE64MIME_DECODER.decode(base64);
  }

  public static byte[] base64MimeDecode(byte[] base64) {
    return BASE64MIME_DECODER.decode(base64);
  }
}
