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
package io.vertx.ext.auth.webauthn.impl.metadata;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.LocalMap;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.attestation.AttestationException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * This class will hold the Fido2 Metadata Records.
 */
public final class MetaData {

  /**
   * A mapping of ALG_SIGN hex values (as unsigned shorts) to COSE curve values. Keys should appear as
   * values in a metadata statement's `authenticationAlgorithm` property.
   * <p>
   * From https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html
   * FIDO Registry of Predefined Values - 3.6.1 Authentication Algorithms
   */
  public static final int ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = 0x0001;
  public static final int ALG_SIGN_SECP256R1_ECDSA_SHA256_DER = 0x0002;
  public static final int ALG_SIGN_RSASSA_PSS_SHA256_RAW = 0x0003;
  public static final int ALG_SIGN_RSASSA_PSS_SHA256_DER = 0x0004;
  public static final int ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW = 0x0005;
  public static final int ALG_SIGN_SECP256K1_ECDSA_SHA256_DER = 0x0006;
  public static final int ALG_SIGN_RSASSA_PSS_SHA384_RAW = 0x000A;
  public static final int ALG_SIGN_RSASSA_PSS_SHA512_RAW = 0x000B;
  public static final int ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW = 0x000C;
  public static final int ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW = 0x000D;
  public static final int ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW = 0x000E;
  public static final int ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW = 0x000F;
  public static final int ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW = 0x0010;
  public static final int ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW = 0x0011;
  public static final int ALG_SIGN_ED25519_EDDSA_SHA256_RAW = 0x0012;

  /**
   * A map of ATTESTATION hex values (as unsigned shorts). Values should appear in a metadata
   * statement's `attestationTypes` property.
   * <p>
   * From https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html
   * FIDO Registry of Predefined Values - 3.6.3 Authenticator Attestation Types
   */
  public static final int ATTESTATION_BASIC_FULL = 0x3E07;
  public static final int ATTESTATION_BASIC_SURROGATE = 0x3E08;
  public static final int ATTESTATION_ECDAA = 0x3E09;
  public static final int ATTESTATION_ATTCA = 0x3E0A;

  private final LocalMap<String, MetaDataEntry> store;
  private final WebAuthnOptions options;

  public MetaData(Vertx vertx, WebAuthnOptions options) {
    this.store = vertx.sharedData()
      .getLocalMap(MetaData.class.getName());
    this.options = options;
  }

  public MetaData clear() {
    store.clear();
    return this;
  }

  public int size() {
    return store.size();
  }

  public @Nullable PublicKeyCredential toJOSEAlg(int fido2AlgSign) {
    switch (fido2AlgSign) {
      case ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW:
      case ALG_SIGN_SECP256R1_ECDSA_SHA256_DER:
        return PublicKeyCredential.ES256;
      case ALG_SIGN_RSASSA_PSS_SHA256_RAW:
      case ALG_SIGN_RSASSA_PSS_SHA256_DER:
        return PublicKeyCredential.PS256;
      case ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW:
      case ALG_SIGN_SECP256K1_ECDSA_SHA256_DER:
        return PublicKeyCredential.ES256K;
      case ALG_SIGN_RSASSA_PSS_SHA384_RAW:
        return PublicKeyCredential.PS384;
      case ALG_SIGN_RSASSA_PSS_SHA512_RAW:
        return PublicKeyCredential.PS512;
      case ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW:
        return PublicKeyCredential.RS256;
      case ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW:
        return PublicKeyCredential.RS384;
      case ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW:
        return PublicKeyCredential.RS512;
      case ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW:
        return PublicKeyCredential.RS1;
      case ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW:
        return PublicKeyCredential.ES384;
      case ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW:
        return PublicKeyCredential.ES512;
      case ALG_SIGN_ED25519_EDDSA_SHA256_RAW:
        return PublicKeyCredential.EdDSA;
      default:
        return null;
    }
  }

  public JsonObject verifyMetadata(String aaguid, PublicKeyCredential alg, List<X509Certificate> x5c) throws MetaDataException, AttestationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException {
    return verifyMetadata(aaguid, alg, x5c, null, true);
  }

  public JsonObject verifyMetadata(String aaguid, PublicKeyCredential alg, List<X509Certificate> x5c, boolean includesRoot) throws MetaDataException, AttestationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException {
    return verifyMetadata(aaguid, alg, x5c, null, includesRoot);
  }

  public JsonObject verifyMetadata(String aaguid, PublicKeyCredential alg, List<X509Certificate> x5c, X509Certificate rootCert) throws MetaDataException, AttestationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException {
    return verifyMetadata(aaguid, alg, x5c, rootCert, true);
  }

  @Nullable
  public JsonObject verifyMetadata(String aaguid, PublicKeyCredential alg, List<X509Certificate> x5c, X509Certificate rootCert, boolean includesRoot) throws MetaDataException, AttestationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException {
    // If available, validate attestation alg and x5c with info in the metadata statement
    MetaDataEntry entry = store.get(aaguid);
    if (entry != null) {
      entry.checkValid();

      // Make sure the alg in the attestation statement matches the one specified in the metadata
      if (alg != toJOSEAlg(entry.statement().getInteger("authenticationAlgorithm"))) {
        throw new AttestationException("Attestation alg did not match metadata auth alg");
      }

      if (x5c != null) {
        // make a copy before we start
        x5c = new ArrayList<>(x5c);

        // Using MDS or Metadata Statements, for each attestationRoot in attestationRootCertificates:
        // append attestation root to the end of the header.x5c, and try verifying certificate chain.
        // If none succeed, throw an error
        JsonArray attestationRootCertificates = entry.statement().getJsonArray("attestationRootCertificates");

        if (attestationRootCertificates == null || attestationRootCertificates.size() == 0) {
          if (rootCert != null) {
            x5c.add(rootCert);
          }
          CertificateHelper.checkValidity(x5c, includesRoot, options.getRootCrls());
        } else {
          boolean chainValid = false;
          for (int i = 0; i < attestationRootCertificates.size(); i++) {
            try {
              // add the metadata root certificate
              x5c.add(JWS.parseX5c(attestationRootCertificates.getString(i)));
              CertificateHelper.checkValidity(x5c, options.getRootCrls());
              chainValid = true;
              break;
            } catch (CertificateException e) {
              // remove the previously added certificate
              x5c.remove(x5c.size() - 1);
              // continue
            }
          }
          if (!chainValid) {
            throw new AttestationException("Certificate Chain not valid for metadata");
          }
        }
      }

      return entry.statement();
    }

    if (x5c != null) {
      // make a copy before we start
      x5c = new ArrayList<>(x5c);

      if (rootCert != null) {
        x5c.add(rootCert);
      }
      CertificateHelper.checkValidity(x5c, includesRoot, options.getRootCrls());
    }
    return null;
  }

  public MetaData loadMetadata(MetaDataEntry entry) {
    JsonObject json = entry.statement();
    String aaguid = json.getString("aaguid");
    if ("fido2".equals(json.getString("protocolFamily"))) {
      if (aaguid == null) {
        throw new IllegalArgumentException("Statement doesn't contain {aaguid}");
      }

      store.put(aaguid, entry);
    }
    return this;
  }
}
