package io.vertx.ext.auth.webauthn.impl.attestation.tpm;

import io.vertx.core.buffer.Buffer;

import static io.vertx.ext.auth.webauthn.impl.attestation.TPMAttestation.*;

public class PubArea {

  private final int type;
  private final int nameAlg;
  private final long objectAttributes;
  private final byte[] authPolicy;
  private final int symmetric;
  private final int scheme;
  private final byte[] unique;
  private int keyBits;
  private long exponent;
  private int curveID;
  private int kdf;

  public PubArea(byte[] data) {
    this(Buffer.buffer(data));
  }

  public PubArea(Buffer pubBuffer) {
    int pos = 0;
    int len;

    type = pubBuffer.getUnsignedShort(pos);
    pos += 2;
    nameAlg = pubBuffer.getUnsignedShort(pos);
    pos += 2;

    // Get some authenticator attributes(?)
    objectAttributes = pubBuffer.getUnsignedInt(pos);
    pos += 4;

    // Slice out the authPolicy of dynamic length
    len = pubBuffer.getUnsignedShort(pos);
    pos += 2;
    authPolicy = pubBuffer.getBytes(pos, pos + len);
    pos += len;

    // Extract additional curve params according to type
    if (type == TPM_ALG_RSA) {
      // read 10 bytes
      symmetric = pubBuffer.getUnsignedShort(pos);
      pos+=2;
      scheme = pubBuffer.getUnsignedShort(pos);
      pos+=2;
      keyBits = pubBuffer.getUnsignedShort(pos);
      pos+=2;
      exponent = pubBuffer.getUnsignedInt(pos);
      pos+=4;
    } else if (type == TPM_ALG_ECC) {
      // read 8 bytes
      symmetric = pubBuffer.getUnsignedShort(pos);
      pos+=2;
      scheme = pubBuffer.getUnsignedShort(pos);
      pos+=2;
      curveID = pubBuffer.getUnsignedShort(pos);
      pos+=4;
      kdf = pubBuffer.getUnsignedShort(pos);
      pos+=2;
    } else {
      throw new IllegalArgumentException("Unexpected type: " + type);
    }

    // Slice out unique of dynamic length
    len = pubBuffer.getUnsignedShort(pos);
    pos+=2;
    unique = pubBuffer.getBytes(pos, pos + len);
  }

  public int getType() {
    return type;
  }

  public int getNameAlg() {
    return nameAlg;
  }

  public long getObjectAttributes() {
    return objectAttributes;
  }

  public byte[] getAuthPolicy() {
    return authPolicy;
  }

  public int getSymmetric() {
    return symmetric;
  }

  public int getScheme() {
    return scheme;
  }

  public int getKeyBits() {
    return keyBits;
  }

  public long getExponent() {
    return exponent;
  }

  public int getCurveID() {
    return curveID;
  }

  public int getKdf() {
    return kdf;
  }

  public byte[] getUnique() {
    return unique;
  }
}
