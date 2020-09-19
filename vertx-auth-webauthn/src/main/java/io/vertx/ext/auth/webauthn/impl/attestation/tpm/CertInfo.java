package io.vertx.ext.auth.webauthn.impl.attestation.tpm;

import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.webauthn.PublicKeyCredential;

public class CertInfo {

  public static final long TPM_GENERATED = 0xFF544347L;

  /**
   * a special four byte constant stating that this is TPM generated structure.
   * Must be set to TPM_GENERATED(0xFF544347)
   */
  private final long magic;

  /**
   * algorithm used for attestation
   */
  private final int type;

  /**
   * a name of a parent entity. Ignore
   */
  private final byte[] qualifiedSigner;

  /**
   * contains hash of the attsToBeSigned.
   * The hashing algorithm is specified by the “alg” field
   */
  private final byte[] extraData;

  /**
   * contains information about TPP clock state.
   * Clock, resetCount, restartCount and safe fields. Ignore
   */
  private final byte[] clockInfo;

  /**
   * TPM-vendor-specific value identifying the version number of the firmware
   */
  private final byte[] firmwareVersion;

  /**
   * a concatenation of hashing algorithm identifier and the hash of the pubArea.
   * More in verification section
   */
  private final byte[] attestedName;

  /**
   * Synthetic value from the first 2 bytes from attestedName
   */
  private final int nameAlg;

  /**
   * Ignore
   */
  private final byte[] qualifiedName;

  public CertInfo(byte[] data) {
    this(Buffer.buffer(data));
  }

  public CertInfo(Buffer certBuffer) {
    int pos = 0;
    int len;
    // Get a magic constant
    magic = certBuffer.getUnsignedInt(pos);
    pos += 4;
    // Determine the algorithm used for attestation
    type = certBuffer.getUnsignedShort(pos);
    pos += 2;
    // The name of a parent entity, can be ignored
    len = certBuffer.getUnsignedShort(pos);
    pos += 2;
    qualifiedSigner = certBuffer.getBytes(pos, pos + len);
    pos += len;
    // Get the expected hash of `attsToBeSigned`
    len = certBuffer.getUnsignedShort(pos);
    pos += 2;
    extraData = certBuffer.getBytes(pos, pos + len);
    pos += len;
    // Information about the TPM device's internal clock, can be ignored
    clockInfo = certBuffer.getBytes(pos, pos + 17);
    pos += 17;
    // TPM device firmware version
    firmwareVersion = certBuffer.getBytes(pos, pos + 8);
    pos += 8;
    // Attested Name
    len = certBuffer.getUnsignedShort(pos);
    pos += 2;
    attestedName = certBuffer.getBytes(pos, pos + len);
    nameAlg = certBuffer.getUnsignedShort(pos);
    pos += len;
    // Attested qualified name, can be ignored
    len = certBuffer.getUnsignedShort(pos);
    pos += 2;
    qualifiedName = certBuffer.getBytes(pos, pos + len);
  }

  public long getMagic() {
    return magic;
  }

  public int getType() {
    return type;
  }

  public byte[] getQualifiedSigner() {
    return qualifiedSigner;
  }

  public byte[] getExtraData() {
    return extraData;
  }

  public byte[] getClockInfo() {
    return clockInfo;
  }

  public byte[] getFirmwareVersion() {
    return firmwareVersion;
  }

  public byte[] getAttestedName() {
    return attestedName;
  }

  public byte[] getQualifiedName() {
    return qualifiedName;
  }

  public int getNameAlg() {
    return nameAlg;
  }
}
