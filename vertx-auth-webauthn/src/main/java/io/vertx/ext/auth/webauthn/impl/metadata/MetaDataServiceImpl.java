package io.vertx.ext.auth.webauthn.impl.metadata;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static io.vertx.core.json.impl.JsonUtil.BASE64_DECODER;
import static io.vertx.ext.auth.impl.Codec.base64Decode;

public class MetaDataServiceImpl implements MetaDataService {

  private static final Logger LOG = LoggerFactory.getLogger(MetaDataServiceImpl.class);

  private final WebAuthnOptions options;
  private final SimpleHttpClient httpClient;
  private final JWT jwt;

  private final MetaData metadata;

  public MetaDataServiceImpl(Vertx vertx, WebAuthnOptions options) {
    VertxInternal vertx1 = (VertxInternal) vertx;
    this.options = options;
    this.httpClient = new SimpleHttpClient(vertx, "vertx-auth", new HttpClientOptions());
    this.jwt = new JWT().allowEmbeddedKey(true);
    this.metadata = new MetaData(vertx, options);
  }

  @Override
  public Future<Boolean> fetchTOC(String toc) {
    return httpClient
      .fetch(HttpMethod.GET, toc, null, null)
      .compose(res -> {

        JsonObject payload;
        String error = null;

        Buffer body = res.body();

        if (body == null) {
          return Future.failedFuture("null JWT");
        }

        try {
          // verify jwt
          JsonObject json = jwt.decode(body.toString(), true, options.getRootCrls());
          // verify cert chain
          JsonArray chain = json.getJsonObject("header").getJsonArray("x5c");
          List<X509Certificate> certChain = new ArrayList<>();

          for (int i = 0; i < chain.size(); i++) {
            // "x5c" (X.509 Certificate Chain) Header Parameter
            // https://tools.ietf.org/html/rfc7515#section-4.1.6
            // states:
            // Each string in the array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
            // [ITU.X690.2008] PKIX certificate value.
            certChain.add(JWS.parseX5c(base64Decode(chain.getString(i))));
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

        } catch (RuntimeException | CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                 SignatureException | NoSuchProviderException e) {
          // the toc signature is not valid.
          // decode it anyway but don't trust any of it's entries
          try {
            error = e.getMessage();
            payload = JWT.parse(body.toString()).getJsonObject("payload");
          } catch (RuntimeException re) {
            return Future.failedFuture(re);
          }
        }

        try {
          if (payload == null) {
            return Future.failedFuture("Could not parse TOC");
          } else {
            if (payload.containsKey("legalHeader")) {
              LOG.info(payload.getString("legalHeader"));
            }

            JsonArray entries = payload.getJsonArray("entries");

            final List<Future> futures = new ArrayList<>(entries.size());
            final String e = error;

            entries.forEach(el -> futures.add(addEntry(e, (JsonObject) el)));

            return CompositeFuture
              .all(futures)
              .map(true)
              .otherwise(false);
          }
        } catch (RuntimeException e) {
          return Future.failedFuture(e);
        }
      });
  }

  private Future<Void> addEntry(String error, JsonObject entry) {
    if (entry.containsKey("url")) {
      // MDSv2
      return httpClient.
        fetch(HttpMethod.GET, entry.getString("url"), null, null)
        .compose(res -> {
          Buffer body = res.body();

          if (body == null) {
            return Future.failedFuture("null JWT");
          }

          try {
            metadata.loadMetadata(new MetaDataEntry(entry, body.getBytes(), error));
            return Future.succeededFuture();
          } catch (RuntimeException | NoSuchAlgorithmException e) {
            return Future.failedFuture(e);
          }
        });
    } else if (entry.containsKey("metadataStatement") && entry.getJsonObject("metadataStatement").getInteger("schema", 0) == 3) {
      // likely MDSv3
      try {
        metadata.loadMetadata(new MetaDataEntry(entry, entry.getJsonObject("metadataStatement"), error));
        return Future.succeededFuture();
      } catch (RuntimeException e) {
        return Future.failedFuture(e);
      }
    } else {
      // unknown
      return Future.failedFuture("Invalid metadataStatement (no url or metadataStatement with schema == 3)");
    }
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
    } catch (SignatureException | AttestationException | NoSuchAlgorithmException | CertificateException |
             MetaDataException | InvalidKeyException | NoSuchProviderException e) {
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
