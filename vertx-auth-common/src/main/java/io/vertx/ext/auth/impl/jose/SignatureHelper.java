/*
 * Copyright 2017 Red Hat, Inc.
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
package io.vertx.ext.auth.impl.jose;

/**
 * Helper functions to convert from DER to JWS and vice versa.
 */
public final class SignatureHelper {

  private SignatureHelper() {
    throw new RuntimeException("Should not be instantiated.");
  }

  /**
   * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
   * R + S format expected by ECDSA JWS.
   *
   * @param derSignature    The ASN1./DER-encoded. Must not be {@code null}.
   * @param signatureLength The length for the JWS signature.
   * @return The ECDSA JWS encoded signature.
   * @throws RuntimeException If the ASN.1/DER signature format is invalid.
   */
  public static byte[] toJWS(final byte[] derSignature, int signatureLength) {

    if (derSignature.length < 8 || derSignature[0] != 48) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    int offset;
    if (derSignature[1] > 0) {
      offset = 2;
    } else if (derSignature[1] == (byte) 0x81) {
      offset = 3;
    } else {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    byte rLength = derSignature[offset + 1];

    int i = rLength;
    while ((i > 0)
      && (derSignature[(offset + 2 + rLength) - i] == 0))
      i--;

    byte sLength = derSignature[offset + 2 + rLength + 1];

    int j = sLength;
    while ((j > 0)
      && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0))
      j--;

    int rawLen = Math.max(i, j);
    rawLen = Math.max(rawLen, signatureLength / 2);

    if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
      || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
      || derSignature[offset] != 2
      || derSignature[offset + 2 + rLength] != 2) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    final byte[] concatSignature = new byte[2 * rawLen];

    System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
    System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

    return concatSignature;
  }

  /**
   * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
   * the JCA verifier.
   *
   * @param jwsSignature The JWS signature, consisting of the
   *                     concatenated R and S values. Must not be
   *                     {@code null}.
   * @return The ASN.1/DER encoded signature.
   * @throws RuntimeException If the ECDSA JWS signature format is invalid.
   */
  public static byte[] toASN1(byte[] jwsSignature) {

    int rawLen = jwsSignature.length / 2;

    int i = rawLen;

    while ((i > 0)
      && (jwsSignature[rawLen - i] == 0))
      i--;

    int j = i;

    if (jwsSignature[rawLen - i] < 0) {
      j += 1;
    }

    int k = rawLen;

    while ((k > 0)
      && (jwsSignature[2 * rawLen - k] == 0))
      k--;

    int l = k;

    if (jwsSignature[2 * rawLen - k] < 0) {
      l += 1;
    }

    int len = 2 + j + 2 + l;

    if (len > 255) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    int offset;

    final byte[] derSignature;

    if (len < 128) {
      derSignature = new byte[2 + 2 + j + 2 + l];
      offset = 1;
    } else {
      derSignature = new byte[3 + 2 + j + 2 + l];
      derSignature[1] = (byte) 0x81;
      offset = 2;
    }

    derSignature[0] = 48;
    derSignature[offset++] = (byte) len;
    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) j;

    System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

    offset += j;

    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) l;

    System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

    return derSignature;
  }

  private static boolean byteAtIndexIs(byte[] data, int idx, int expected) {
    if (data == null) {
      return false;
    }
    if (data.length <= idx) {
      return false;
    }
    return data[idx] == expected;
  }

  private static boolean byteAtIndexLte(byte[] data, int idx, int expected) {
    if (data == null) {
      return false;
    }
    if (data.length <= idx) {
      return false;
    }
    if (data[idx] <= 0) {
      return false;
    }
    return data[idx] <= expected;
  }

  /**
   * A signature in ASN1 format is a sequence of 2 values.
   * This method verifies that the content contains the right markers and length.
   */
  public static boolean isASN1(byte[] sig) {
    // seq
    if (!byteAtIndexIs(sig, 0, 48)) {
      return false;
    }

    int offset;

    if (sig.length < 128) {
      offset = 0;
    } else {
      // handle extended
      if (!byteAtIndexIs(sig, 1, (byte) 0x81)) {
        return false;
      }
      offset = 1;
    }

    // sequence

    // verify the sequence byte length
    if (!byteAtIndexIs(sig, offset + 1, sig.length - 2)) {
      return false;
    }

    offset = offset + 2;

    for (int i = 0; i < 2; i++) {
      // element [0]
      // check if the tag is 2 (integer)
      if (!byteAtIndexIs(sig, offset, 2)) {
        return false;
      }
      // verify the sequence[0] byte length
      if (!byteAtIndexLte(sig, offset + 1, sig.length - offset - 2)) {
        return false;
      }
      // element [1]
      offset = offset + sig[offset + 1] + 2;
    }

    return offset == sig.length;
  }
}
