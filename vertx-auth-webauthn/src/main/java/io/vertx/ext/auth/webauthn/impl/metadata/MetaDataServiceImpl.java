package io.vertx.ext.auth.webauthn.impl.metadata;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.webauthn.Authenticator;
import io.vertx.ext.auth.webauthn.MetaDataService;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.attestation.AttestationException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static io.vertx.core.json.impl.JsonUtil.BASE64_DECODER;

public class MetaDataServiceImpl implements MetaDataService {

  private static final Base64.Decoder BASE64DEC = Base64.getDecoder();
  private static final Logger LOG = LoggerFactory.getLogger(MetaDataServiceImpl.class);

  private final VertxInternal vertx;
  private final WebAuthnOptions options;
  private final SimpleHttpClient httpClient;
  private final JWT jwt;

  private final MetaData metadata;

  public MetaDataServiceImpl(Vertx vertx, WebAuthnOptions options) {
    this.vertx = (VertxInternal) vertx;
    this.options = options;
    this.httpClient = new SimpleHttpClient(vertx, "vertx-auth", new HttpClientOptions());
    this.jwt = new JWT().allowEmbeddedKey(true);
    this.metadata = new MetaData(vertx, options);
  }

  @Override
  public Future<Boolean> fetchTOC(String toc) {

    final Promise<Boolean> promise = vertx.promise();
    httpClient.fetch(HttpMethod.GET, toc, null, null)
      .onFailure(promise::fail)
      .onSuccess(res -> {

        JsonObject payload;
        String error = null;

        try {
          // verify jwt
          JsonObject json = jwt.decode(res.body().toString(), true);
          // verify cert chain
          JsonArray chain = json.getJsonObject("header").getJsonArray("x5c");
          List<X509Certificate> certChain = new ArrayList<>();

          for (int i = 0; i < chain.size(); i++) {
            // "x5c" (X.509 Certificate Chain) Header Parameter
            // https://tools.ietf.org/html/rfc7515#section-4.1.6
            // states:
            // Each string in the array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
            // [ITU.X690.2008] PKIX certificate value.
            certChain.add(JWS.parseX5c(BASE64DEC.decode(chain.getString(i).getBytes(StandardCharsets.UTF_8))));
          }
          // add the root certificate
          certChain.add(options.getRootCertificate("mds"));
          List<X509CRL> crls = options.getRootCrls();
          if (crls == null || crls.size() == 0) {
            // warning: we don't have CRLs loaded
            LOG.warn("No CRLs loaded for MDS Certificate");
          }
          CertificateHelper.checkValidity(certChain, crls);

          payload = json.getJsonObject("payload");

        } catch (RuntimeException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
          // the toc signature is not valid.
          // decode it anyway but don't trust any of it's entries
          try {
            error = e.getMessage();
            payload = JWT.parse(res.body().toString()).getJsonObject("payload");
          } catch (RuntimeException re) {
            promise.fail(re);
            return;
          }
        }

        try {
          if (payload == null) {
            promise.fail("Could not parse TOC");
          } else {
            if (payload.containsKey("legalHeader")) {
              LOG.info(payload.getString("legalHeader"));
            }

            JsonArray entries = payload.getJsonArray("entries");

            final String e = error;
            final AtomicInteger cnt = new AtomicInteger(entries.size());
            final AtomicBoolean success = new AtomicBoolean(true);

            entries.forEach(el ->
              addEntry(e, (JsonObject) el)
                .onFailure(err -> {
                  LOG.error("Failed to add entry", err);
                  success.set(false);
                  if (cnt.decrementAndGet() == 0) {
                    promise.complete(success.get());
                  }
                })
                .onComplete(done -> {
                  if (cnt.decrementAndGet() == 0) {
                    promise.complete(success.get());
                  }
                }));
          }
        } catch (RuntimeException e) {
          promise.fail(e);
        }
      });

    return promise.future();
  }

  private Future<Void> addEntry(String error, JsonObject entry) {
    final Promise<Void> promise = vertx.promise();
    if (entry.containsKey("url")) {
      // MDSv2
      httpClient.fetch(HttpMethod.GET, entry.getString("url"), null, null)
        .onFailure(promise::fail)
        .onSuccess(res -> {
          try {
            metadata.loadMetadata(new MetaDataEntry(entry, res.body().getBytes(), error));
            promise.complete();
          } catch (RuntimeException | NoSuchAlgorithmException e) {
            promise.fail(e);
          }
        });
    } else if (entry.containsKey("metadataStatement") && entry.getJsonObject("metadataStatement").getInteger("schema", 0) == 3) {
      // likely MDSv3
      try {
        metadata.loadMetadata(new MetaDataEntry(entry, entry.getJsonObject("metadataStatement"), error));
        promise.complete();
      } catch (RuntimeException | NoSuchAlgorithmException e) {
        promise.fail(e);
      }
    } else {
      // unknown
      promise.fail("Invalid metadataStatement (no url or metadataStatement with schema == 3)");
    }

    return promise.future();
  }

  @Override
  public MetaDataService addStatement(JsonObject statement) {
    metadata.loadMetadata(new MetaDataEntry(statement));
    return this;
  }

  @Override
  public MetaDataService flush() {
    metadata.clear();
    return this;
  }

  @Override
  public JsonObject verify(Authenticator authenticator) {
    try {
      boolean includesRoot;
      switch (authenticator.getFmt()) {
        case "none":
        case "android-safetynet":
        case "tpm":
          includesRoot = false;
          break;
        default:
          includesRoot = true;
      }
      return metadata.verifyMetadata(
        authenticator.getAaguid(),
        authenticator.getAttestationCertificates().getAlg(),
        parseX5c(authenticator.getAttestationCertificates().getX5c()),
        includesRoot);
    } catch (SignatureException | AttestationException | NoSuchAlgorithmException | CertificateException | MetaDataException | InvalidKeyException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  private static List<X509Certificate> parseX5c(List<String> x5c) throws CertificateException {
    List<X509Certificate> certChain = new ArrayList<>();

    if (x5c == null || x5c.size() == 0) {
      return certChain;
    }

    for (String s : x5c) {
      certChain.add(JWS.parseX5c(BASE64_DECODER.decode(s)));
    }

    return certChain;
  }


  public MetaData metadata() {
    return metadata;
  }
}
