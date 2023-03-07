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

package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.asn.ASN1;
import io.vertx.ext.auth.webauthn.AttestationCertificates;
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.AuthData;
import io.vertx.ext.auth.webauthn.impl.attestation.tpm.CertInfo;
import io.vertx.ext.auth.webauthn.impl.attestation.tpm.PubArea;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;
import static io.vertx.ext.auth.impl.asn.ASN1.*;
import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.*;
import static io.vertx.ext.auth.webauthn.impl.metadata.MetaData.*;

/**
 * Implementation of the FIDO "tpm" attestation check.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public class TPMAttestation implements Attestation {

  public static final int TPM_ALG_ERROR = 0x0000;
  public static final int TPM_ALG_RSA = 0x0001;
  public static final int TPM_ALG_SHA = 0x0004;
  public static final int TPM_ALG_SHA1 = 0x0004;
  public static final int TPM_ALG_HMAC = 0x0005;
  public static final int TPM_ALG_AES = 0x0006;
  public static final int TPM_ALG_MGF1 = 0x0007;
  public static final int TPM_ALG_KEYEDHASH = 0x0008;
  public static final int TPM_ALG_XOR = 0x000a;
  public static final int TPM_ALG_SHA256 = 0x000b;
  public static final int TPM_ALG_SHA384 = 0x000c;
  public static final int TPM_ALG_SHA512 = 0x000d;
  public static final int TPM_ALG_NULL = 0x0010;
  public static final int TPM_ALG_SM3_256 = 0x0012;
  public static final int TPM_ALG_SM4 = 0x0013;
  public static final int TPM_ALG_RSASSA = 0x0014;
  public static final int TPM_ALG_RSAES = 0x0015;
  public static final int TPM_ALG_RSAPSS = 0x0016;
  public static final int TPM_ALG_OAEP = 0x0017;
  public static final int TPM_ALG_ECDSA = 0x0018;
  public static final int TPM_ALG_ECDH = 0x0019;
  public static final int TPM_ALG_ECDAA = 0x001a;
  public static final int TPM_ALG_SM2 = 0x001b;
  public static final int TPM_ALG_ECSCHNORR = 0x001c;
  public static final int TPM_ALG_ECMQV = 0x001d;
  public static final int TPM_ALG_KDF1_SP800_56A = 0x0020;
  public static final int TPM_ALG_KDF2 = 0x0021;
  public static final int TPM_ALG_KDF1_SP800_108 = 0x0022;
  public static final int TPM_ALG_ECC = 0x0023;
  public static final int TPM_ALG_SYMCIPHER = 0x0025;
  public static final int TPM_ALG_CAMELLIA = 0x0026;
  public static final int TPM_ALG_CTR = 0x0040;
  public static final int TPM_ALG_OFB = 0x0041;
  public static final int TPM_ALG_CBC = 0x0042;
  public static final int TPM_ALG_CFB = 0x0043;
  public static final int TPM_ALG_ECB = 0x0044;

  public static final int TPM_ST_ATTEST_CERTIFY = 0x8017;

  private static final List<String> TPM_MANUFACTURERS = Arrays.asList(
    "id:414D4400", // AMD
    "id:41544D4C", // Atmel
    "id:4252434D", // Broadcom
    "id:49424d00", // IBM
    "id:49465800", // Infineon
    "id:494E5443", // Intel
    "id:4C454E00", // Lenovo
    "id:4E534D20", // National Semiconductor
    "id:4E545A00", // Nationz
    "id:4E544300", // Nuvoton Technology
    "id:51434F4D", // Qualcomm
    "id:534D5343", // SMSC
    "id:53544D20", // ST Microelectronics
    "id:534D534E", // Samsung
    "id:534E5300", // Sinosun
    "id:54584E00", // Texas Instruments
    "id:57454300", // Winbond
    "id:524F4343", // Fuzhouk Rockchip
    "id:FFFFF1D0" // FIDO Alliance
  );

  @Override
  public String fmt() {
    return "tpm";
  }

  @Override
  public AttestationCertificates validate(WebAuthnOptions options, MetaData metadata, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
    // typical attestation object:
    //{
    //	"fmt": "tpm",
    //	"authData": "base64",
    //	"attStmt": {
    //		"ver": "2.0",
    //		"alg": -65535,
    //		"sig": "base64",
    //		"x5c": ["base64"],
    //		"certInfo": "base64",
    //		"pubArea": "base64"
    //	}
    //}
    try {
      byte[] clientDataHash = hash("SHA-256", clientDataJSON);

      JsonObject attStmt = attestation.getJsonObject("attStmt");

      // To verify attestation we need to do two things:
      // verify structures and verify signature and chain

      // Verifying structures
      // 1. Check that "ver" is set to "2.0"
      if (!attStmt.getString("ver").equals("2.0")) {
        throw new AttestationException("expected TPM version 2.0");
      }

      // 2. Parse "pubArea".
      PubArea pubArea = new PubArea(base64UrlDecode(attStmt.getString("pubArea")));
      // 3. Verify that the public key specified by the parameters and unique fields of pubArea is
      //    identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
      JsonObject cosePublicKey = authData.getCredentialPublicKeyJson();
      if (pubArea.getType() == TPM_ALG_RSA) {
        // extract the RSA parameters from the COSE CBOR
        byte[] n = base64UrlDecode(cosePublicKey.getString("-1"));
        byte[] e = base64UrlDecode(cosePublicKey.getString("-2"));
        long exponent = pubArea.getExponent();
        // If `exponent` is equal to 0x00, then exponent is the default RSA exponent of 2^16+1 (65537)
        if (exponent == 0x00) {
          exponent = 65537;
        }
        // Do some bit shifting to get to an integer
        if (exponent != e[0] + (e[1] << 8) + (e[2] << 16)) {
          throw new AttestationException("Unexpected public key exp");
        }
        // 4. Check that pubArea.unique is set to the same public key,
        //    as the one in “authData” struct.
        if (!MessageDigest.isEqual(pubArea.getUnique(), n)) {
          throw new AttestationException("PubArea unique is not same as credentialPublicKey");
        }
      } else if (pubArea.getType() == TPM_ALG_ECC) {
        // extract the RSA parameters from the COSE CBOR
        byte[] crv = base64UrlDecode(cosePublicKey.getString("-1"));
        byte[] x = base64UrlDecode(cosePublicKey.getString("-2"));
        byte[] y = base64UrlDecode(cosePublicKey.getString("-3"));
        // Do some bit shifting to get to an integer
        if (pubArea.getCurveID() != crv[0] + (crv[1] << 8)) {
          throw new AttestationException("Unexpected public key crv");
        }
        // 4. Check that pubArea.unique is set to the same public key,
        //    as the one in “authData” struct.
        if (!MessageDigest.isEqual(pubArea.getUnique(), Buffer.buffer().appendBytes(x).appendBytes(y).getBytes())) {
          throw new AttestationException("PubArea unique is not same as public key x and y");
        }
      } else {
        throw new AttestationException("Unsupported pubArea.type" + pubArea.getType());
      }

      // 5. Parse “certInfo”.
      CertInfo certInfo = new CertInfo(base64UrlDecode(attStmt.getString("certInfo")));
      // 6. Check that certInfo.magic is set to TPM_GENERATED(0xFF544347).
      if (certInfo.getMagic() != CertInfo.TPM_GENERATED) {
        throw new AttestationException("certInfo had bad magic number");
      }
      // 7. Check that certInfo.type is set to TPM_ST_ATTEST_CERTIFY(0x8017).
      if (certInfo.getType() != TPM_ST_ATTEST_CERTIFY) {
        throw new AttestationException("Wrong type. expected 'TPM_ST_ATTEST_CERTIFY'");
      }
      // 8. Hash pubArea to create pubAreaHash using the nameAlg in attested
      String alg;
      switch (certInfo.getNameAlg()) {
        case TPM_ALG_SHA1:
          alg = "SHA1";
          break;
        case TPM_ALG_SHA256:
          alg = "SHA-256";
          break;
        case TPM_ALG_SHA384:
          alg = "SHA-384";
          break;
        case TPM_ALG_SHA512:
          alg = "SHA-512";
          break;
        default:
          throw new AttestationException("Unsupported algorithm: " + pubArea.getNameAlg());
      }
      byte[] pubAreaHash = hash(alg, base64UrlDecode(attStmt.getString("pubArea")));
      // 9. Concatenate attested.nameAlg and pubAreaHash to create attestedName.
      byte[] attestedName = Buffer.buffer()
        .appendByte(certInfo.getAttestedName()[0])
        .appendByte(certInfo.getAttestedName()[1])
        .appendBytes(pubAreaHash)
        .getBytes();
      // 10. Check that certInfo.attested.name is equals to attestedName.
      if (!MessageDigest.isEqual(certInfo.getAttestedName(), attestedName)) {
        throw new AttestationException("Attested name comparison failed");
      }
      // 11. Concatenate authData with clientDataHash to create attToBeSigned
      byte[] attToBeSigned = Buffer.buffer()
        .appendBytes(authData.getRaw())
        .appendBytes(clientDataHash)
        .getBytes();
      // 12. Hash attToBeSigned using the algorithm specified in attStmt.alg
      //     to create attToBeSignedHash
      switch (attStmt.getInteger("alg")) {
        case -7:
        case -37:
        case -47:
        case -257:
          alg = "SHA-256";
          break;
        case -35:
        case -38:
        case -258:
          alg = "SHA-384";
          break;
        case -36:
        case -39:
        case -259:
          alg = "SHA-512";
          break;
        case -65535:
          alg = "SHA1";
          break;
        default:
          throw new AttestationException("Unsupported algorithm: " + attStmt.getInteger("alg"));
      }
      byte[] attToBeSignedHash = hash(alg, attToBeSigned);
      // 13. Check that certInfo.extraData is equals to attToBeSignedHash.
      if (!MessageDigest.isEqual(certInfo.getExtraData(), attToBeSignedHash)) {
        throw new AttestationException("CertInfo extra data did not equal hashed attestation");
      }

      // The attestation structures are correct
      // Verify the signature

      // 1. Pick a leaf AIK certificate of the x5c array and parse it.
      List<X509Certificate> x5c = parseX5c(attStmt.getJsonArray("x5c"));
      if (x5c.size() == 0) {
        throw new AttestationException("no certificates in x5c field");
      }
      X509Certificate leafCert = x5c.get(0);
      CertificateHelper.CertInfo leafCertInfo = CertificateHelper.getCertInfo(leafCert);
      // 2. Check that attCert is of version 3(ASN1 INT 2)
      if (leafCertInfo.version() != 3) {
        throw new AttestationException("Batch certificate version MUST be 3(ASN1 2)");
      }
      // 3. Check that attCert basic constraints for CA is set to -1
      if (leafCertInfo.basicConstraintsCA() != -1) {
        throw new AttestationException("Batch certificate basic constraints CA MUST be -1");
      }
      // 4. Check that Subject sequence is empty.
      if (!leafCertInfo.isEmpty()) {
        throw new AttestationException("Certificate subject was not empty");
      }
      // 5. Validity checks
      leafCert.checkValidity();

      // 6. Check that certificate contains subjectAltName(2.5.29.17) extension,
      //    and check that tcpaTpmManufacturer(2.23.133.2.1) field is set to the
      //    existing manufacturer ID. You can find list of TPM_MANUFACTURERS.
      byte[] subjectAltName = leafCert.getExtensionValue("2.5.29.17");
      ASN1.ASN extension = ASN1.parseASN1(subjectAltName);
      //OCTET STRING (64 byte)
      //  SEQUENCE (1 elem)
      //    [4] (1 elem)
      //      SEQUENCE (1 elem)
      //        SET (3 elem)
      //          SEQUENCE (2 elem)
      //            OBJECT IDENTIFIER 2.23.133.2.3 tcpaTpmVersion (TCPA Attribute)
      //            UTF8String id:13
      //          SEQUENCE (2 elem)
      //            OBJECT IDENTIFIER 2.23.133.2.2 tcpaTpmModel (TCPA Attribute)
      //            UTF8String NPCT6xx
      //          SEQUENCE (2 elem)
      //            OBJECT IDENTIFIER 2.23.133.2.1 tcpaTpmManufacturer (TCPA Attribute)
      //            UTF8String id:4E544300

      // parse the initial OCTET STRING body
      if (!extension.is(OCTET_STRING)) {
        throw new AttestationException("2.5.29.17 Extension is not an ASN.1 OCTET_STRING");
      }
      ASN1.ASN root = ASN1.parseASN1(extension.binary(0));
      // root should be of type SEQUENCE
      if (!root.is(SEQUENCE)) {
        throw new AttestationException("2.5.29.17 Extension OCTET_STRING is not an ASN.1 SEQUENCE");
      }
      ASN1.ASN set = root
        .object(0, CONTEXT_SPECIFIC | OCTET_STRING)
        // SEQUENCE
        .object(0, SEQUENCE)
        // SET
        .object(0, SET);

      for (int i = 0; i < set.length(); i++) {
        ASN1.ASN el = set.object(i);
        ASN1.ASN oid = el.object(0, OBJECT_IDENTIFIER);
        ASN1.ASN val = el.object(1, UTF8_STRING);

        if (MessageDigest.isEqual(oid.binary(0), new byte[]{0x67, (byte) 0x81, 0x05, 0x02, 0x01})) {
          if (!TPM_MANUFACTURERS.contains(new String(val.binary(0), StandardCharsets.UTF_8))) {
            throw new AttestationException("Unknown Manufacturer id");
          }
        }
      }

      // 7. Check that certificate contains extKeyUsage(2.5.29.37) extension
      //    and it must contain tcg-kp-AIKCertificate (2.23.133.8.3) OID.
      byte[] extKeyUsage = leafCert.getExtensionValue("2.5.29.37");
      extension = ASN1.parseASN1(extKeyUsage);
      //OCTET STRING (9 byte)
      //  SEQUENCE (1 elem)
      //    OBJECT IDENTIFIER 2.23.133.8.3

      // parse the initial OCTET STRING body
      if (!extension.is(OCTET_STRING)) {
        throw new AttestationException("2.5.29.37 Extension is not an ASN.1 OCTET_STRING");
      }
      // root should be of type SEQUENCE
      root = ASN1.parseASN1(extension.binary(0));
      if (!root.is(SEQUENCE)) {
        throw new AttestationException("2.5.29.37 Extension OCTET_STRING is not an ASN.1 SEQUENCE");
      }
      boolean found = false;
      for (int i = 0; i < root.length(); i++) {
        ASN1.ASN el = root.object(i, OBJECT_IDENTIFIER);
        // tcg-kp-AIKCertificate
        if (MessageDigest.isEqual(el.binary(0), new byte[]{0x67, (byte) 0x81, 0x05, 0x08, 0x03})) {
          found = true;
          break;
        }
      }
      if (!found) {
        throw new AttestationException("2.5.29.37 Extension SEQUENCE does not contain OBJECT_IDENTIFIER 2.23.133.8.3");
      }
      // 8. If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension,
      // then check that its value set to the AAGUID returned by the authenticator in authData.
      byte[] idFidoGenCeAaguid = leafCert.getExtensionValue("1.3.6.1.4.1.45724.1.1.4");
      if (idFidoGenCeAaguid != null) {
        extension = ASN1.parseASN1(idFidoGenCeAaguid);
        if (!extension.is(OCTET_STRING)) {
          throw new AttestationException("1.3.6.1.4.1.45724.1.1.4 Extension is not an ASN.1 OCTECT string!");
        }
        // parse the octet as ASN.1 and expect it to se a sequence
        extension = parseASN1(extension.binary(0));
        if (!extension.is(OCTET_STRING)) {
          throw new AttestationException("1.3.6.1.4.1.45724.1.1.4 Extension is not an ASN.1 OCTECT string!");
        }
        // match check
        if (!MessageDigest.isEqual(extension.binary(0), authData.getAaguid())) {
          throw new AttestationException("Certificate id-fido-gen-ce-aaguid extension does not match authData");
        }
      }

      // If available, validate attestation alg and x5c with info in the metadata statement
      JsonObject statement = metadata.verifyMetadata(
        authData.getAaguidString(),
        PublicKeyCredential.valueOf(attStmt.getInteger("alg")),
        x5c,
        false);

      if (statement != null) {
        // verify that the statement allows this type of attestation
        if (!statementAttestationTypesContains(statement, ATTESTATION_ATTCA) && !statementAttestationTypesContains(statement, ATTESTATION_BASIC_FULL)) {
          throw new AttestationException("Metadata does not indicate support for attca/basic_full attestations");
        }
      }

      // 9. Verify signature over certInfo with the public key extracted from AIK certificate.
      verifySignature(
        PublicKeyCredential.valueOf(attStmt.getInteger("alg")),
        leafCert,
        base64UrlDecode(attStmt.getString("sig")),
        base64UrlDecode(attStmt.getString("certInfo")));

      return new AttestationCertificates()
        .setAlg(PublicKeyCredential.valueOf(attStmt.getInteger("alg")))
        .setX5c(attStmt.getJsonArray("x5c"));

    } catch (MetaDataException | NoSuchAlgorithmException | CertificateException | InvalidKeyException |
             SignatureException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
      throw new AttestationException(e);
    }
  }
}
