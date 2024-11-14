package io.vertx.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import com.webauthn4j.data.*;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.toc.StatusReport;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.webauthn4j.async.metadata.FidoMDS3MetadataBLOBAsyncProvider;
import com.webauthn4j.async.metadata.HttpAsyncClient;
import com.webauthn4j.async.metadata.anchor.MetadataBLOBBasedTrustAnchorAsyncRepository;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn4j.Attestation;
import io.vertx.ext.auth.webauthn4j.Authenticator;
import io.vertx.ext.auth.webauthn4j.RelyingParty;
import io.vertx.ext.auth.webauthn4j.WebAuthn4J;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JOptions;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JCredentials;
import io.vertx.ext.auth.webauthn4j.impl.VertxHttpAsyncClient;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

@RunWith(VertxUnitRunner.class)
public class EmulatorTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

	private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

	private final DummyStore database = new DummyStore();

	String rpName = "ACME Corporation";
	String username = "fromage";
	String displayName = "Stephane Epardaud";
	Origin origin = new Origin("http://localhost");

	@Rule
	public final RunTestOnContext rule = new RunTestOnContext();

	@Before
	public void resetDatabase() {
		database.clear();
	}


	@Test
	public void testMetadata(TestContext should) {
		final Async test = should.async();

		// this is not testing via the WebAuthn API, because I can't actually generate any attestation that would be validated by the FIDO metatata,
		// as only real hardware can sign those. Emulation would not help, and real captured data would end up expiring.
		// but I can make sure the vert.x http client works
		HttpAsyncClient httpClient = new VertxHttpAsyncClient(rule.vertx());
		Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (Entry<String, X509Certificate> entry : new WebAuthn4JOptions().getRootCertificates().entrySet()) {
			trustAnchors.add(new TrustAnchor(entry.getValue(), null));
		}
		FidoMDS3MetadataBLOBAsyncProvider blobAsyncProvider = new FidoMDS3MetadataBLOBAsyncProvider(objectConverter, FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT, httpClient, trustAnchors);
		MetadataBLOBBasedTrustAnchorAsyncRepository something = new MetadataBLOBBasedTrustAnchorAsyncRepository(blobAsyncProvider);
		blobAsyncProvider.provide()
				.thenCompose(metadataBLOB -> {
			Assert.assertNotEquals(0, metadataBLOB.getPayload().getEntries().size());
			for (MetadataBLOBPayloadEntry entry : metadataBLOB.getPayload().getEntries()) {
				if(entry.getAaguid() != null
						// the following are things that are in the implementation of webauthn4j that will filter what find() returns, so make sure
						// they pass
						&& !entry.getMetadataStatement().getAttestationRootCertificates().isEmpty()
                    && checkMetadataBLOBPayloadEntry(entry, something.isNotFidoCertifiedAllowed(), something.isSelfAssertionSubmittedAllowed())
                    && checkSurrogateMetadataStatementAttestationRootCertificate(entry.getMetadataStatement())) {
					return something.find(entry.getAaguid());
				}
			}
			Assert.fail("Could not find a single AAGUID in the metadata");
			return null; // never reached
		}).thenAccept(foundTrustAnchors -> {
			Assert.assertNotEquals(0, foundTrustAnchors.size());
		}).handle((v, x) -> {
			if(x != null) {
				should.fail(x);
			} else {
				test.complete();
			}
			return null;
		});
	}

  // copied from webauthn4j as it is not exported to the outside of the module
  private static boolean checkMetadataBLOBPayloadEntry( MetadataBLOBPayloadEntry metadataBLOBPayloadEntry, boolean notFidoCertifiedAllowed, boolean selfAssertionSubmittedAllowed) {
    List<StatusReport> statusReports = metadataBLOBPayloadEntry.getStatusReports();
    for (StatusReport report : statusReports) {
      switch (report.getStatus()) {
        //Info statuses
        case UPDATE_AVAILABLE:
          // UPDATE_AVAILABLE itself doesn't mean security issue. If security related update is available,
          // corresponding status report is expected to be added to the report list.
          break;

        //Certification Related statuses
        case FIDO_CERTIFIED:
        case FIDO_CERTIFIED_L1:
        case FIDO_CERTIFIED_L1_PLUS:
        case FIDO_CERTIFIED_L2:
        case FIDO_CERTIFIED_L2_PLUS:
        case FIDO_CERTIFIED_L3:
        case FIDO_CERTIFIED_L3_PLUS:
          break;
        case NOT_FIDO_CERTIFIED:
          if (notFidoCertifiedAllowed) {
            break;
          }
          else {
            return false;
          }
        case SELF_ASSERTION_SUBMITTED:
          if (selfAssertionSubmittedAllowed) {
            break;
          }
          else {
            return false;
          }

          // Security Notification statuses
        case ATTESTATION_KEY_COMPROMISE:
        case USER_VERIFICATION_BYPASS:
        case USER_KEY_REMOTE_COMPROMISE:
        case USER_KEY_PHYSICAL_COMPROMISE:
        case REVOKED:
        default:
          return false;
      }
    }
    return true;
  }

  // copied from webauthn4j as it is not exported to the outside of the module
  private static boolean checkSurrogateMetadataStatementAttestationRootCertificate(MetadataStatement metadataStatement) {
    boolean isSurrogate = metadataStatement != null && metadataStatement.getAttestationTypes().stream().allMatch(type -> type.equals(AuthenticatorAttestationType.BASIC_SURROGATE));

    if (isSurrogate) {
      return metadataStatement.getAttestationRootCertificates().isEmpty();
    }
    return true;
  }

  @Test
	public void testDefaults(TestContext should) throws DataConversionException, InterruptedException, ExecutionException {
		final Async test = should.async();

		WebAuthn4J webAuthN = WebAuthn4J.create(
				rule.vertx(),
				new WebAuthn4JOptions().setRelyingParty(new RelyingParty().setName(rpName)))
	      .credentialStorage(database);

		WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
		ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

		testRegistration(webAuthN, clientPlatform, should)
		.flatMap(v -> testAuthentication(webAuthN, clientPlatform, should))
		.onFailure(should::fail)
		.onSuccess(v -> test.complete());
	}

	@Test
	public void testDirect(TestContext should) throws DataConversionException, InterruptedException, ExecutionException {
		final Async test = should.async();

		X509Certificate rootCA = TestAttestationUtil.load3tierTestRootCACertificate();

		WebAuthn4J webAuthN = WebAuthn4J.create(
				rule.vertx(),
				new WebAuthn4JOptions().setRelyingParty(new RelyingParty().setName(rpName))
				.setAttestation(Attestation.DIRECT)
				.addRootCertificate(rootCA))
	      .credentialStorage(database);

		WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
		ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

		testRegistration(webAuthN, clientPlatform, should)
		.flatMap(v -> testAuthentication(webAuthN, clientPlatform, should))
		.onFailure(should::fail)
		.onSuccess(v -> test.complete());
	}

	@Test
	public void testDirectWithoutCA(TestContext should) throws DataConversionException, InterruptedException, ExecutionException {
		final Async test = should.async();

		WebAuthn4J webAuthN = WebAuthn4J.create(
				rule.vertx(),
				new WebAuthn4JOptions().setRelyingParty(new RelyingParty().setName(rpName))
				.setAttestation(Attestation.DIRECT))
	      .credentialStorage(database);

		WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
		ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

		testRegistration(webAuthN, clientPlatform, should)
		.flatMap(v -> testAuthentication(webAuthN, clientPlatform, should))
		.onFailure(x -> {
			while(x.getCause() != null) {
				x = x.getCause();
			}
			Assert.assertEquals("Path does not chain with any of the trust anchors", x.getMessage());
			test.complete();
		})
		.onSuccess(v -> should.fail("Verification should not have passed without CA configured"));
	}

	private Future<?> testRegistration(WebAuthn4J webAuthN, ClientPlatform clientPlatform, TestContext should) {
		DefaultChallenge challenge = new DefaultChallenge();
		RegistrationRequest registrationRequest = createRegistrationRequest(clientPlatform, origin.getHost(), challenge, username, displayName, should);
		// dummy request
		JsonObject request = new JsonObject()
				.put("id", should.get("credId"))
				.put("rawId", should.get("credId"))
				.put("type", "public-key")
				.put("response", new JsonObject()
						.put("attestationObject", Base64UrlUtil.encodeToString(registrationRequest.getAttestationObject()))
						.put("clientDataJSON", Base64UrlUtil.encodeToString(registrationRequest.getClientDataJSON())));

		return webAuthN
		.authenticate(
				new WebAuthn4JCredentials()
				.setUsername(username)
				.setOrigin(origin.toString())
				.setDomain(origin.getHost())
				.setChallenge(Base64UrlUtil.encodeToString(challenge.getValue()))
				.setWebauthn(request))
		.flatMap(user -> {
			assertNotNull(user);
			// make sure we have the right user name
			assertEquals(username, user.principal().getString("userName"));
			// also make sure we saved the user in the DB under that username
			return database.find(username, null);
		})
		.onSuccess(authenticators -> {
			assertNotNull(authenticators);
			assertEquals(1, authenticators.size());
			Authenticator authenticator = authenticators.get(0);
			// Check username, credid, counter, publicKey
			assertEquals(username, authenticator.getUserName());
			assertEquals(should.get("credId"), authenticator.getCredID());
			should.put("counter", authenticator.getCounter());
			assertEquals(should.get("publicKey"), authenticator.getPublicKey());
		});

	}

	private RegistrationRequest createRegistrationRequest(ClientPlatform clientPlatform, String rpId, Challenge challenge, String username, String displayName, TestContext should){
		AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
				new AuthenticatorSelectionCriteria(
						AuthenticatorAttachment.CROSS_PLATFORM,
						true,
						UserVerificationRequirement.REQUIRED);

		PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

		PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity(new byte[32], username, displayName);

		AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
		PublicKeyCredentialCreationOptions credentialCreationOptions
		= new PublicKeyCredentialCreationOptions(
				new PublicKeyCredentialRpEntity(rpId, "example.com"),
				publicKeyCredentialUserEntity,
				challenge,
				Collections.singletonList(publicKeyCredentialParameters),
				null,
				Collections.emptyList(),
				authenticatorSelectionCriteria,
				AttestationConveyancePreference.DIRECT,
				extensions
				);
		PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
		AuthenticatorAttestationResponse registrationRequest = credential.getResponse();

		// save cred id and public key to verify later
        AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
        byte[] attestedCredentialDataBytes = authenticatorDataConverter.extractAttestedCredentialData(registrationRequest.getAuthenticatorData(objectConverter));
        AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(attestedCredentialDataBytes);
        should.put("credId", Base64UrlUtil.encodeToString(attestedCredentialData.getCredentialId()));
        should.put("publicKey", Base64UrlUtil.encodeToString(objectConverter.getCborConverter().writeValueAsBytes(attestedCredentialData.getCOSEKey())));
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensionResults = credential.getClientExtensionResults();
		Set<String> transports = Collections.emptySet();
		String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
		return new RegistrationRequest(
				registrationRequest.getAttestationObject(),
				registrationRequest.getClientDataJSON(),
				clientExtensionJSON,
				transports
				);
	}

	private Future<?> testAuthentication(WebAuthn4J webAuthN, ClientPlatform clientPlatform, TestContext should) {
		DefaultChallenge challenge = new DefaultChallenge();
		AuthenticationRequest authenticationRequest = createAuthenticationRequest(clientPlatform, origin.getHost(), challenge, username, displayName);
		// dummy request
		JsonObject request = new JsonObject()
				.put("id", should.get("credId"))
				.put("rawId", should.get("credId"))
				.put("type", "public-key")
				.put("response", new JsonObject()
						.put("signature", Base64UrlUtil.encodeToString(authenticationRequest.getSignature()))
						.put("authenticatorData", Base64UrlUtil.encodeToString(authenticationRequest.getAuthenticatorData()))
						.put("clientDataJSON", Base64UrlUtil.encodeToString(authenticationRequest.getClientDataJSON())));

		return webAuthN
		.authenticate(
				new WebAuthn4JCredentials()
				.setUsername(username)
				.setOrigin(origin.toString())
				.setDomain(origin.getHost())
				.setChallenge(Base64UrlUtil.encodeToString(challenge.getValue()))
				.setWebauthn(request))
		.flatMap(user -> {
			assertNotNull(user);
			// make sure we have the right user name
			assertEquals(username, user.principal().getString("userName"));
			// also make sure we saved the user in the DB under that username
			return database.find(username, null);
		})
		.onSuccess(authenticators -> {
			assertNotNull(authenticators);
			assertEquals(1, authenticators.size());
			Authenticator authenticator = authenticators.get(0);
			// Check username, credid, counter, publicKey
			assertEquals(username, authenticator.getUserName());
			assertEquals(should.get("credId"), authenticator.getCredID());
			assertEquals(should.<Long>get("counter") + 1, authenticator.getCounter());
			assertEquals(should.get("publicKey"), authenticator.getPublicKey());
		});
	}

	private AuthenticationRequest createAuthenticationRequest(ClientPlatform clientPlatform, String rpId, Challenge challenge, String username, String displayName) {
        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0l,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );

        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getResponse();
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensionResults = credential.getClientExtensionResults();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);

        return new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        clientExtensionJSON,
                        authenticationRequest.getSignature()
                );

	}

}
