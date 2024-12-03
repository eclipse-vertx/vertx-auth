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

package io.vertx.ext.auth.webauthn4j.impl;

import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;
import static io.vertx.ext.auth.impl.Codec.base64UrlEncode;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.webauthn4j.async.WebAuthnAsyncManager;
import com.webauthn4j.async.anchor.KeyStoreTrustAnchorAsyncRepository;
import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.async.metadata.FidoMDS3MetadataBLOBAsyncProvider;
import com.webauthn4j.async.metadata.HttpAsyncClient;
import com.webauthn4j.async.metadata.anchor.MetadataBLOBBasedTrustAnchorAsyncRepository;
import com.webauthn4j.async.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.packed.PackedAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.tpm.TPMAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement;
import com.webauthn4j.data.attestation.statement.AppleAnonymousAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.attestation.statement.TPMAttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.internal.logging.Logger;
import io.vertx.core.internal.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.CertificateHelper.CertInfo;
import io.vertx.ext.auth.prng.VertxContextPRNG;
import io.vertx.ext.auth.webauthn4j.*;
import io.vertx.ext.auth.webauthn4j.COSEAlgorithm;

public class WebAuthn4JImpl implements WebAuthn4J {

  private static final Logger LOG = LoggerFactory.getLogger(WebAuthn4J.class);

  private final VertxContextPRNG random;
  private final WebAuthn4JOptions options;

  private CredentialStorage credentialStorage;

  private final WebAuthnAsyncManager webAuthnManager;
  private final ObjectConverter objectConverter = new ObjectConverter();

  public WebAuthn4JImpl(Vertx vertx, WebAuthn4JOptions options) {
    random = VertxContextPRNG.current(vertx);
    this.options = options;

    if (options == null) {
      throw new IllegalArgumentException("options cannot be null!");
    }

    // verify that RP is not null
    if (options.getRelyingParty() == null) {
      throw new IllegalArgumentException("options.relyingParty cannot be null!");
    }

    // verify that RP.name is not null
    if (options.getRelyingParty().getName() == null) {
      throw new IllegalArgumentException("options.relyingParty.name cannot be null!");
    }

    if(options.getAttestation() != Attestation.NONE) {
    	TrustAnchorAsyncRepository something;
    	Set<TrustAnchor> trustAnchors = new HashSet<>();
    	try {
    		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    		keyStore.load(null, null);
    		for (Entry<String, X509Certificate> entry : options.getRootCertificates().entrySet()) {
    			CertInfo info = CertificateHelper.getCertInfo(entry.getValue());
    			keyStore.setCertificateEntry(info.subject("CN"), entry.getValue());
    			trustAnchors.add(new TrustAnchor(entry.getValue(), null));
    		}

    		// FIXME CLRs are not supported yet
    		something = new KeyStoreTrustAnchorAsyncRepository(keyStore);
    	} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
    		throw new RuntimeException(e);
    	}
    	if(options.isUseMetadata()) {
    		HttpAsyncClient httpClient = new VertxHttpAsyncClient(vertx);
    		FidoMDS3MetadataBLOBAsyncProvider blobAsyncProvider = new FidoMDS3MetadataBLOBAsyncProvider(objectConverter, FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT, httpClient, trustAnchors);
    		something = new MetadataBLOBBasedTrustAnchorAsyncRepository(blobAsyncProvider);
    	}

    	webAuthnManager = new WebAuthnAsyncManager(
    			Arrays.asList(
    					new FIDOU2FAttestationStatementAsyncVerifier(),
    					new PackedAttestationStatementAsyncVerifier(),
    					new TPMAttestationStatementAsyncVerifier(),
    					new AndroidKeyAttestationStatementAsyncVerifier(),
    					new AndroidSafetyNetAttestationStatementAsyncVerifier(),
    					new AppleAnonymousAttestationStatementAsyncVerifier()
    					),
    			new DefaultCertPathTrustworthinessAsyncVerifier(something),
    			new DefaultSelfAttestationTrustworthinessAsyncVerifier(),
    			objectConverter
    			);

    } else {
        webAuthnManager = WebAuthnAsyncManager.createNonStrictWebAuthnAsyncManager(objectConverter);
    }
  }

  private String randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return base64UrlEncode(buff);
  }

  private void putOpt(JsonObject json, String key, Object value) {
    if (value != null) {
      if (value instanceof Enum<?>) {
        json.put(key, value.toString());
        return;
      }
      if (value instanceof JsonObject) {
        if (((JsonObject) value).isEmpty()) {
          return;
        }
      }
      if (value instanceof JsonArray) {
        if (((JsonArray) value).isEmpty()) {
          return;
        }
      }
      json.put(key, value);
    }
  }

  private void addOpt(JsonArray json, Object value) {
    if (value != null) {
      if (value instanceof Enum<?>) {
        json.add(value.toString());
        return;
      }
      if (value instanceof JsonObject) {
        if (((JsonObject) value).isEmpty()) {
          return;
        }
      }
      if (value instanceof JsonArray) {
        if (((JsonArray) value).isEmpty()) {
          return;
        }
      }
      json.add(value);
    }
  }

  private static String uUIDtoBase64Url(UUID uuid) {
    Buffer buffer = Buffer.buffer(16);
    buffer.setLong(0, uuid.getMostSignificantBits());
    buffer.setLong(8, uuid.getLeastSignificantBits());
    return base64UrlEncode(buffer.getBytes());
  }

  @Override
  public WebAuthn4J credentialStorage(CredentialStorage credentialStorage) {
    if (credentialStorage == null) {
      throw new IllegalArgumentException("CredentialStorage cannot be null");
    }
    this.credentialStorage = credentialStorage;
    return this;
  }

  @Override
  public Future<JsonObject> createCredentialsOptions(JsonObject user) {

	  return credentialStorage.find(user.getString("name"), null)
      .map(authenticators -> {
        // empty structure with all required fields
        JsonObject json = new JsonObject()
          .put("rp", new JsonObject())
          .put("user", new JsonObject())
          .put("challenge", randomBase64URLBuffer(options.getChallengeLength()))
          .put("pubKeyCredParams", new JsonArray())
          .put("authenticatorSelection", new JsonObject());

        // put non null values for RelyingParty
        putOpt(json.getJsonObject("rp"), "id", options.getRelyingParty().getId());
        putOpt(json.getJsonObject("rp"), "name", options.getRelyingParty().getName());

        // put non null values for User
        putOpt(json.getJsonObject("user"), "id", uUIDtoBase64Url(UUID.randomUUID()));
        putOpt(json.getJsonObject("user"), "name", user.getString("name"));
        putOpt(json.getJsonObject("user"), "displayName", user.getString("displayName"));
        putOpt(json.getJsonObject("user"), "icon", user.getString("icon"));
        // put the public key credentials parameters
        for (COSEAlgorithm pubKeyCredParam : options.getPubKeyCredParams()) {
          addOpt(
            json.getJsonArray("pubKeyCredParams"),
            new JsonObject()
              .put("alg", pubKeyCredParam.coseId())
              .put("type", "public-key"));
        }
        // optional timeout
        putOpt(json, "timeout", options.getTimeoutInMilliseconds());
        // optional excluded credentials
        if (!authenticators.isEmpty()) {
          JsonArray transports = new JsonArray();

          for (AuthenticatorTransport transport : options.getTransports()) {
            addOpt(transports, transport.toString());
          }

          JsonArray excludeCredentials = new JsonArray();
          for (Authenticator key : authenticators) {
            JsonObject credentialDescriptor = new JsonObject()
              .put("type", key.getType())
              .put("id", key.getCredID());
            // add optional transports to the descriptor
            putOpt(credentialDescriptor, "transports", transports);
            // add to the excludeCredentials list
            addOpt(excludeCredentials, credentialDescriptor);
          }
          // add the the response json
          putOpt(json, "excludeCredentials", excludeCredentials);
        }
        // optional authenticator selection
        putOpt(json.getJsonObject("authenticatorSelection"), "authenticatorAttachment", options.getAuthenticatorAttachment());
        putOpt(json.getJsonObject("authenticatorSelection"), "residentKey", options.getResidentKey());
        putOpt(json.getJsonObject("authenticatorSelection"), "requireResidentKey", options.getResidentKey() == ResidentKey.REQUIRED);
        putOpt(json.getJsonObject("authenticatorSelection"), "userVerification", options.getUserVerification());
        // optional attestation
        putOpt(json, "attestation", options.getAttestation());
        // optional extensions
        putOpt(json, "extensions", options.getExtensions());

        return json;
      });
  }

  @Override
  public Future<JsonObject> getCredentialsOptions(String name) {

    // https://w3c.github.io/webauthn/#dictionary-assertion-options
    JsonObject json = new JsonObject()
      .put("challenge", randomBase64URLBuffer(options.getChallengeLength()));
    putOpt(json, "timeout", options.getTimeoutInMilliseconds());
    putOpt(json, "rpId", options.getRelyingParty().getId());
    putOpt(json, "userVerification", options.getUserVerification());
    putOpt(json, "extensions", options.getExtensions());

    // we allow Resident Credentials or (RK) requests
    // this means that name is not required
    switch (options.getResidentKey()) {
      case REQUIRED:
      case PREFERRED:
        // we prefer RK, so we don't need a name
        return Future.succeededFuture(json);
      case DISCOURAGED:
        // we don't want RK, so we need a name
        if (name == null) {
          return Future.failedFuture("Name is required for non RK requests");
        }
        break;
    }
    // fallback to non RK requests
    return credentialStorage.find(name, null)
      .compose(authenticators -> {
        if (authenticators.isEmpty()) {
          // fail as the user has never register an authenticator
          return Future.failedFuture("No authenticators registered for user: " + name);
        }
        // there are authenticators, continue...
        return Future.succeededFuture(authenticators);
      })
      .map(authenticators -> {
        JsonArray allowCredentials = new JsonArray();

        JsonArray transports = new JsonArray();
        if (options.getTransports() != null) {
          for (AuthenticatorTransport transport : options.getTransports()) {
            transports.add(transport.toString());
          }
        }

        for (Authenticator key : authenticators) {
          String credId = key.getCredID();
          if (credId != null) {
            JsonObject credential = new JsonObject()
              .put("type", "public-key")
              .put("id", credId);
            putOpt(credential, "transports", transports);

            allowCredentials.add(credential);
          }
        }
        putOpt(json, "allowCredentials", allowCredentials);

        return json;
      });
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    try {
      // cast
      WebAuthn4JCredentials authInfo;
      try {
        authInfo = (WebAuthn4JCredentials) credentials;
      } catch (ClassCastException e) {
        throw new CredentialValidationException("Invalid credentials type", e);
      }
      // check
      authInfo.checkValid(null);
      // The basic data supplied with any kind of validation is:
      //    {
      //      "rawId": "base64url",
      //      "id": "base64url",
      //      "response": {
      //        "clientDataJSON": "base64url"
      //      }
      //    }
      final JsonObject webauthn = authInfo.getWebauthn();
      JsonObject response = webauthn.getJsonObject("response");

      // verifying the webauthn response starts here:

      // regardless of the request the first 6 steps are always executed:

      // 1. Decode ClientDataJSON
      // 2. Check that challenge is set to the challenge you’ve sent
      // 3. Check that origin is set to the the origin of your website. If it’s not raise the alarm, and log the event, because someone tried to phish your user
      // 4. Check that type is set to either “webauthn.create” or “webauthn.get”.
      // 5. Parse authData or authenticatorData.
      // 6. Check that flags have UV or UP flags set.

      // STEP #1
      // The client data (or session) is a base64 url encoded JSON
      // we specifically keep track of the binary representation as it will be
      // used later on during validation to verify signatures for tampering
      final byte[] clientDataJSON = base64UrlDecode(response.getString("clientDataJSON"));
      JsonObject clientData = new JsonObject(Buffer.buffer(clientDataJSON));

      // Step #2
      // Verify challenge is match with session
      if (!authInfo.getChallenge().equals(clientData.getString("challenge"))) {
        return Future.failedFuture("Challenges don't match!");
      }

      // Step #3
      // If the auth info object contains an Origin we can verify it:
      if (authInfo.getOrigin() != null) {
        if (!authInfo.getOrigin().equals(clientData.getString("origin"))) {
          return Future.failedFuture("Origins don't match!"+clientData.getString("origin"));
        }
      }

      final String username = authInfo.getUsername();

      // Step #4
      // Verify that the type is valid and that is "webauthn.create" or "webauthn.get"
      if (!clientData.containsKey("type")) {
        return Future.failedFuture("Missing type on client data");
      }

      switch (clientData.getString("type")) {
        case "webauthn.create":
          // we always need a username to register
          if (username == null) {
            return Future.failedFuture("username can't be null!");
          }

          return verifyWebAuthNCreate(response, authInfo, clientDataJSON)
        		  .compose(authrInfo -> {
        			  // by default the store can upsert if a credential is missing, the user has been verified so it is valid
        			  // the store however might disallow this operation
        			  authrInfo.setUserName(username);

        			  // the create challenge is complete we can finally save this
        			  // new authenticator to the storage
        			  return credentialStorage.storeCredential(authrInfo)
        					  .compose(stored -> {
        						  User user = User.create(authrInfo.toJson());
        						  // metadata "amr"
        						  if ((authrInfo.getFlags() & AuthData.USER_PRESENT) != 0) {
        							  user.principal().put("amr", Arrays.asList("user", "swk"));
        						  } else {
        							  user.principal().put("amr", Collections.singletonList("swk"));
        						  }

        						  return Future.succeededFuture(user);
        					  });

        		  });
        case "webauthn.get":

          // username is optional in most cases
          if(options.getResidentKey() == ResidentKey.DISCOURAGED
             && username == null) {
            return Future.failedFuture("username can't be null!");
          }

          // this is required
        	String credentialId = webauthn.getString("id");
          return credentialStorage.find(username, credentialId)
            .compose(authenticators -> {
              Objects.requireNonNull(authenticators);
              if(authenticators.isEmpty()) {
                // No valid authenticator was found
                return Future.failedFuture("Cannot find authenticator with id: " + webauthn.getString("id"));
              } else if (authenticators.size() == 1) {
                Authenticator authenticator = authenticators.get(0);
                return verifyWebAuthNGet(response, authInfo, clientDataJSON, authenticator)
                    .compose(counter -> {
                      // update the counter on the authenticator
                      authenticator.setCounter(counter);
                      // update the credential (the important here is to update the counter)
                      return credentialStorage.updateCounter(authenticator)
                          .compose(stored -> {
                            User user = User.create(authenticator.toJson());
                            // metadata "amr"
                            if ((authenticator.getFlags() & AuthData.USER_PRESENT) != 0) {
                              user.principal().put("amr", Arrays.asList("user", "swk"));
                            } else {
                              user.principal().put("amr", Collections.singletonList("swk"));
                            }

                            return Future.succeededFuture(user);
                          });
                    });
              } else {
                return Future.failedFuture("Found multiple authenticators for id: " + webauthn.getString("id") + " and username: "+username
                    +" which breaks the contract of CredentialStorage");
              }
            });
        default:
          return Future.failedFuture("Can not determine type of response!");
      }
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }
  }

  /**
   * Verify credentials creation from client
   *
   * @param request        - The request as received by the {@link #authenticate(Credentials)} method.
   * @param clientDataJSON - Binary session data
   */
  private Future<Authenticator> verifyWebAuthNCreate(JsonObject response, WebAuthn4JCredentials authInfo, byte[] clientDataJSON) {

	  // client properties
	  byte[] attestationObject = base64UrlDecode(response.getString("attestationObject"));
	  Set<String> transports = new HashSet<>();

	  JsonArray transportsArray = response.getJsonArray("transports");
	  if(transportsArray != null) {
	    for (Object object : transportsArray) {
        if(object instanceof String) {
          transports.add((String) object);
        } else {
          return Future.failedFuture(new WebAuthn4JException("Invalid transport: "+object));
        }
      }
	  }
	  JsonObject clientExtensionResults = response.getJsonObject("clientExtensionResults");
	  // not optimal
	  String clientExtensionJSON = clientExtensionResults != null ? clientExtensionResults.encode() : null;

	  RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);

	  // server properties
	  ServerProperty serverProperty = getServerProperty(authInfo);

	  // expectations
	  boolean userVerificationRequired = options.getUserVerification() == UserVerification.REQUIRED;
	  boolean userPresenceRequired = options.isUserPresenceRequired();

	  List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>(options.getPubKeyCredParams().size());
	  for (COSEAlgorithm COSEAlgorithm : options.getPubKeyCredParams()) {
      pubKeyCredParams.add(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(COSEAlgorithm.coseId())));
    }
	  RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);

	  return Future.fromCompletionStage(webAuthnManager.verify(registrationRequest, registrationParameters))
			  .map(registrationData -> {
			    AttestationCertificates attestationCertificates = convertAttestationCertificates(registrationData.getAttestationObject().getAttestationStatement());
			    COSEKey coseKey = registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey();
			    return new Authenticator()
			        .setFmt(registrationData.getAttestationObject().getAttestationStatement().getFormat())
			        .setAaguid(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid().toString())
			        .setPublicKey(base64UrlEncode(objectConverter.getCborConverter().writeValueAsBytes(coseKey)))
			        .setCounter(registrationData.getAttestationObject().getAuthenticatorData().getSignCount())
			        .setCredID(base64UrlEncode(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId()))
			        .setAttestationCertificates(attestationCertificates)
			        .setFlags(registrationData.getAttestationObject().getAuthenticatorData().getFlags());
	  });
  }

  private AttestationCertificates convertAttestationCertificates(AttestationStatement attestationStatement) {
    AttestationCertificates attestationCertificates = new AttestationCertificates();
    if(attestationStatement instanceof CertificateBaseAttestationStatement) {
      // certificates
      AttestationCertificatePath x5c = ((CertificateBaseAttestationStatement)attestationStatement).getX5c();
      if(x5c != null) {
        attestationCertificates.setX5c(x5c.stream().map(cert -> {
          try {
            return base64UrlEncode(cert.getEncoded());
          } catch (CertificateEncodingException e) {
            throw new WebAuthn4JException(e);
          }
        }).collect(Collectors.toList()));
      }
      // algo
      if(attestationStatement instanceof AndroidKeyAttestationStatement){
        attestationCertificates.setAlg(COSEAlgorithm.valueOf((int) ((AndroidKeyAttestationStatement)attestationStatement).getAlg().getValue()));
      } else if(attestationStatement instanceof AndroidSafetyNetAttestationStatement){
        // hoping the names match
        attestationCertificates.setAlg(COSEAlgorithm.valueOf(((AndroidSafetyNetAttestationStatement)attestationStatement).getResponse().getHeader().getAlg().getName()));
      } else if(attestationStatement instanceof AppleAnonymousAttestationStatement){
        // FIXME: optional, but not read in webauthn4j?
        attestationCertificates.setAlg(null);
      } else if(attestationStatement instanceof FIDOU2FAttestationStatement){
        // seems to be fixed?
        attestationCertificates.setAlg(COSEAlgorithm.valueOf((int) COSEAlgorithmIdentifier.ES256.getValue()));
      } else if(attestationStatement instanceof PackedAttestationStatement){
        attestationCertificates.setAlg(COSEAlgorithm.valueOf((int) ((PackedAttestationStatement)attestationStatement).getAlg().getValue()));
      } else if(attestationStatement instanceof TPMAttestationStatement){
        attestationCertificates.setAlg(COSEAlgorithm.valueOf((int) ((TPMAttestationStatement)attestationStatement).getAlg().getValue()));
      } else {
        throw new WebAuthn4JException("Unsupported attestation statement format: "+attestationStatement.getFormat());
      }
    }
    return attestationCertificates;
  }

  private ServerProperty getServerProperty(WebAuthn4JCredentials authInfo) {
	  Origin origin = Origin.create(authInfo.getOrigin());
	  String rpId = options.getRelyingParty().getId();
	  if(rpId == null) {
		  rpId = origin.getHost();
	  }
	  Challenge challenge = new DefaultChallenge(authInfo.getChallenge());
	  // this is deprecated in Level 3, so ignore it
	  byte[] tokenBindingId = null;
	  return new ServerProperty(origin, rpId, challenge, tokenBindingId);
  }

/**
   * Verify navigator.credentials.get response
   *
   * @param request        - The request as received by the {@link #authenticate(Credentials)} method.
   * @param clientDataJSON - The extracted clientDataJSON
   * @param authenticator     - Credential from Database
   */
  private Future<Long> verifyWebAuthNGet(JsonObject response, WebAuthn4JCredentials request, byte[] clientDataJSON, Authenticator authenticator) {

	  byte[] credentialId = base64UrlDecode(request.getWebauthn().getString("id"));
	  byte[] userHandle = response.containsKey("userHandle") ? base64UrlDecode(response.getString("userHandle")) : null;
	  byte[] authenticatorData = base64UrlDecode(response.getString("authenticatorData"));
    JsonObject clientExtensionResults = response.getJsonObject("clientExtensionResults");
    // not optimal
    String clientExtensionJSON = clientExtensionResults != null ? clientExtensionResults.encode() : null;
	  byte[] signature = base64UrlDecode(response.getString("signature"));

	  AuthenticationRequest authenticationRequest =
		        new AuthenticationRequest(
		                credentialId,
		                userHandle,
		                authenticatorData,
		                clientDataJSON,
		                clientExtensionJSON,
		                signature
		        );

	  // server properties
	  ServerProperty serverProperty = getServerProperty(request);

	  // expectations
	  List<byte[]> allowCredentials = List.of(base64UrlDecode(authenticator.getCredID()));
	  boolean userVerificationRequired = options.getUserVerification() == UserVerification.REQUIRED;
	  boolean userPresenceRequired = options.isUserPresenceRequired();
	  CredentialRecord credentialRecord = loadCredentialRecord(authenticator);

	  AuthenticationParameters authenticationParameters =
			  new AuthenticationParameters(
					  serverProperty,
					  credentialRecord,
					  allowCredentials,
					  userVerificationRequired,
					  userPresenceRequired
					  );


	  return Future.fromCompletionStage(webAuthnManager.verify(authenticationRequest, authenticationParameters))
			  .map(parsedAuthenticatorData -> parsedAuthenticatorData.getAuthenticatorData().getSignCount());
  }

  private CredentialRecord loadCredentialRecord(Authenticator authenticator) {
    // AFAICT, we could reconstruct that from the fmt and certificates, but it doesn't look like it is used
    // apparently only coseKey and counter are used for verification, not the attestation statement.

    // important
    long counter = authenticator.getCounter();
    COSEKey coseKey = objectConverter.getCborConverter().readValue(base64UrlDecode(authenticator.getPublicKey()), COSEKey.class);
    byte[] credentialId = base64UrlDecode(authenticator.getCredID());
    AAGUID aaguid = new AAGUID(authenticator.getAaguid());
    AttestedCredentialData attestedCredentialData = new AttestedCredentialData(aaguid, credentialId, coseKey);

    // Just ignored for verification
    AttestationStatement attestationStatement = null;
    Boolean uvInitialized = null;
    Boolean backupEligible = null;
    Boolean backupState = null;
    AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = null;
    CollectedClientData clientData = null;
    AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = null;
    Set<com.webauthn4j.data.AuthenticatorTransport> transports = null;

	  return new CredentialRecordImpl(attestationStatement, uvInitialized, backupEligible, backupState, counter, attestedCredentialData,
			  authenticatorExtensions, clientData, clientExtensions, transports);
  }
}
