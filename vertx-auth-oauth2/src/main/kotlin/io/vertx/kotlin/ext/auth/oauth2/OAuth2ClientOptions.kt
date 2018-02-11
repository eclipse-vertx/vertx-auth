package io.vertx.kotlin.ext.auth.oauth2

import io.vertx.ext.auth.oauth2.OAuth2ClientOptions
import io.vertx.core.http.Http2Settings
import io.vertx.core.http.HttpVersion
import io.vertx.core.net.JdkSSLEngineOptions
import io.vertx.core.net.JksOptions
import io.vertx.core.net.OpenSSLEngineOptions
import io.vertx.core.net.PemKeyCertOptions
import io.vertx.core.net.PemTrustOptions
import io.vertx.core.net.PfxOptions
import io.vertx.core.net.ProxyOptions
import io.vertx.ext.auth.PubSecKeyOptions
import io.vertx.ext.jwt.JWTOptions

/**
 * A function providing a DSL for building [io.vertx.ext.auth.oauth2.OAuth2ClientOptions] objects.
 *
 * Options describing how an OAuth2  will make connections.
 *
 * @param alpnVersions 
 * @param authorizationPath  Get the Oauth2 authorization resource path. e.g.: /oauth/authorize
 * @param clientID  Set the provider client id
 * @param clientSecret  Set the provider client secret
 * @param clientSecretParameterName  Override the HTTP form field name for client secret
 * @param connectTimeout 
 * @param crlPaths 
 * @param crlValues 
 * @param decoderInitialBufferSize 
 * @param defaultHost 
 * @param defaultPort 
 * @param enabledCipherSuites 
 * @param enabledSecureTransportProtocols 
 * @param extraParameters  Set extra parameters to be sent to the provider on each request
 * @param forceSni 
 * @param headers  Set custom headers to be sent with every request to the provider
 * @param http2ClearTextUpgrade 
 * @param http2ConnectionWindowSize 
 * @param http2MaxPoolSize 
 * @param http2MultiplexingLimit 
 * @param idleTimeout 
 * @param initialSettings 
 * @param introspectionPath  Set the provider token introspection resource path
 * @param jdkSslEngineOptions 
 * @param jwkPath 
 * @param jwtOptions 
 * @param jwtToken 
 * @param keepAlive 
 * @param keyStoreOptions 
 * @param localAddress 
 * @param logActivity 
 * @param logoutPath  Set the provider logout path
 * @param maxChunkSize 
 * @param maxHeaderSize 
 * @param maxInitialLineLength 
 * @param maxPoolSize 
 * @param maxRedirects 
 * @param maxWaitQueueSize 
 * @param maxWebsocketFrameSize 
 * @param maxWebsocketMessageSize 
 * @param metricsName 
 * @param openSslEngineOptions 
 * @param pemKeyCertOptions 
 * @param pemTrustOptions 
 * @param pfxKeyCertOptions 
 * @param pfxTrustOptions 
 * @param pipelining 
 * @param pipeliningLimit 
 * @param protocolVersion 
 * @param proxyOptions 
 * @param pubSecKeys  The provider PubSec key options
 * @param receiveBufferSize 
 * @param reuseAddress 
 * @param reusePort 
 * @param revocationPath  Set the Oauth2 revocation resource path. e.g.: /oauth/revoke
 * @param scopeSeparator  Set the provider scope separator
 * @param sendBufferSize 
 * @param sendUnmaskedFrames 
 * @param site  Root URL for the provider
 * @param soLinger 
 * @param ssl 
 * @param tcpCork 
 * @param tcpFastOpen 
 * @param tcpKeepAlive 
 * @param tcpNoDelay 
 * @param tcpQuickAck 
 * @param tokenPath  Get the Oauth2 token resource path. e.g.: /oauth/token
 * @param trafficClass 
 * @param trustAll 
 * @param trustStoreOptions 
 * @param tryUseCompression 
 * @param useAlpn 
 * @param useBasicAuthorizationHeader  Flag to use HTTP basic auth header with client id, client secret.
 * @param usePooledBuffers 
 * @param userAgent  Set a custom user agent to use when communicating to a provider
 * @param userInfoParameters  Set custom parameters to be sent during the userInfo resource request
 * @param userInfoPath  Set the provider userInfo resource path
 * @param verifyHost 
 *
 * <p/>
 * NOTE: This function has been automatically generated from the [io.vertx.ext.auth.oauth2.OAuth2ClientOptions original] using Vert.x codegen.
 */
fun OAuth2ClientOptions(
  alpnVersions: Iterable<HttpVersion>? = null,
  authorizationPath: String? = null,
  clientID: String? = null,
  clientSecret: String? = null,
  clientSecretParameterName: String? = null,
  connectTimeout: Int? = null,
  crlPaths: Iterable<String>? = null,
  crlValues: Iterable<io.vertx.core.buffer.Buffer>? = null,
  decoderInitialBufferSize: Int? = null,
  defaultHost: String? = null,
  defaultPort: Int? = null,
  enabledCipherSuites: Iterable<String>? = null,
  enabledSecureTransportProtocols: Iterable<String>? = null,
  extraParameters: io.vertx.core.json.JsonObject? = null,
  forceSni: Boolean? = null,
  headers: io.vertx.core.json.JsonObject? = null,
  http2ClearTextUpgrade: Boolean? = null,
  http2ConnectionWindowSize: Int? = null,
  http2MaxPoolSize: Int? = null,
  http2MultiplexingLimit: Int? = null,
  idleTimeout: Int? = null,
  initialSettings: io.vertx.core.http.Http2Settings? = null,
  introspectionPath: String? = null,
  jdkSslEngineOptions: io.vertx.core.net.JdkSSLEngineOptions? = null,
  jwkPath: String? = null,
  jwtOptions: io.vertx.ext.jwt.JWTOptions? = null,
  jwtToken: Boolean? = null,
  keepAlive: Boolean? = null,
  keyStoreOptions: io.vertx.core.net.JksOptions? = null,
  localAddress: String? = null,
  logActivity: Boolean? = null,
  logoutPath: String? = null,
  maxChunkSize: Int? = null,
  maxHeaderSize: Int? = null,
  maxInitialLineLength: Int? = null,
  maxPoolSize: Int? = null,
  maxRedirects: Int? = null,
  maxWaitQueueSize: Int? = null,
  maxWebsocketFrameSize: Int? = null,
  maxWebsocketMessageSize: Int? = null,
  metricsName: String? = null,
  openSslEngineOptions: io.vertx.core.net.OpenSSLEngineOptions? = null,
  pemKeyCertOptions: io.vertx.core.net.PemKeyCertOptions? = null,
  pemTrustOptions: io.vertx.core.net.PemTrustOptions? = null,
  pfxKeyCertOptions: io.vertx.core.net.PfxOptions? = null,
  pfxTrustOptions: io.vertx.core.net.PfxOptions? = null,
  pipelining: Boolean? = null,
  pipeliningLimit: Int? = null,
  protocolVersion: HttpVersion? = null,
  proxyOptions: io.vertx.core.net.ProxyOptions? = null,
  pubSecKeys: Iterable<io.vertx.ext.auth.PubSecKeyOptions>? = null,
  receiveBufferSize: Int? = null,
  reuseAddress: Boolean? = null,
  reusePort: Boolean? = null,
  revocationPath: String? = null,
  scopeSeparator: String? = null,
  sendBufferSize: Int? = null,
  sendUnmaskedFrames: Boolean? = null,
  site: String? = null,
  soLinger: Int? = null,
  ssl: Boolean? = null,
  tcpCork: Boolean? = null,
  tcpFastOpen: Boolean? = null,
  tcpKeepAlive: Boolean? = null,
  tcpNoDelay: Boolean? = null,
  tcpQuickAck: Boolean? = null,
  tokenPath: String? = null,
  trafficClass: Int? = null,
  trustAll: Boolean? = null,
  trustStoreOptions: io.vertx.core.net.JksOptions? = null,
  tryUseCompression: Boolean? = null,
  useAlpn: Boolean? = null,
  useBasicAuthorizationHeader: Boolean? = null,
  usePooledBuffers: Boolean? = null,
  userAgent: String? = null,
  userInfoParameters: io.vertx.core.json.JsonObject? = null,
  userInfoPath: String? = null,
  verifyHost: Boolean? = null): OAuth2ClientOptions = io.vertx.ext.auth.oauth2.OAuth2ClientOptions().apply {

  if (alpnVersions != null) {
    this.setAlpnVersions(alpnVersions.toList())
  }
  if (authorizationPath != null) {
    this.setAuthorizationPath(authorizationPath)
  }
  if (clientID != null) {
    this.setClientID(clientID)
  }
  if (clientSecret != null) {
    this.setClientSecret(clientSecret)
  }
  if (clientSecretParameterName != null) {
    this.setClientSecretParameterName(clientSecretParameterName)
  }
  if (connectTimeout != null) {
    this.setConnectTimeout(connectTimeout)
  }
  if (crlPaths != null) {
    for (item in crlPaths) {
      this.addCrlPath(item)
    }
  }
  if (crlValues != null) {
    for (item in crlValues) {
      this.addCrlValue(item)
    }
  }
  if (decoderInitialBufferSize != null) {
    this.setDecoderInitialBufferSize(decoderInitialBufferSize)
  }
  if (defaultHost != null) {
    this.setDefaultHost(defaultHost)
  }
  if (defaultPort != null) {
    this.setDefaultPort(defaultPort)
  }
  if (enabledCipherSuites != null) {
    for (item in enabledCipherSuites) {
      this.addEnabledCipherSuite(item)
    }
  }
  if (enabledSecureTransportProtocols != null) {
    this.setEnabledSecureTransportProtocols(enabledSecureTransportProtocols.toSet())
  }
  if (extraParameters != null) {
    this.setExtraParameters(extraParameters)
  }
  if (forceSni != null) {
    this.setForceSni(forceSni)
  }
  if (headers != null) {
    this.setHeaders(headers)
  }
  if (http2ClearTextUpgrade != null) {
    this.setHttp2ClearTextUpgrade(http2ClearTextUpgrade)
  }
  if (http2ConnectionWindowSize != null) {
    this.setHttp2ConnectionWindowSize(http2ConnectionWindowSize)
  }
  if (http2MaxPoolSize != null) {
    this.setHttp2MaxPoolSize(http2MaxPoolSize)
  }
  if (http2MultiplexingLimit != null) {
    this.setHttp2MultiplexingLimit(http2MultiplexingLimit)
  }
  if (idleTimeout != null) {
    this.setIdleTimeout(idleTimeout)
  }
  if (initialSettings != null) {
    this.setInitialSettings(initialSettings)
  }
  if (introspectionPath != null) {
    this.setIntrospectionPath(introspectionPath)
  }
  if (jdkSslEngineOptions != null) {
    this.setJdkSslEngineOptions(jdkSslEngineOptions)
  }
  if (jwkPath != null) {
    this.setJwkPath(jwkPath)
  }
  if (jwtOptions != null) {
    this.setJWTOptions(jwtOptions)
  }
  if (jwtToken != null) {
    this.setJWTToken(jwtToken)
  }
  if (keepAlive != null) {
    this.setKeepAlive(keepAlive)
  }
  if (keyStoreOptions != null) {
    this.setKeyStoreOptions(keyStoreOptions)
  }
  if (localAddress != null) {
    this.setLocalAddress(localAddress)
  }
  if (logActivity != null) {
    this.setLogActivity(logActivity)
  }
  if (logoutPath != null) {
    this.setLogoutPath(logoutPath)
  }
  if (maxChunkSize != null) {
    this.setMaxChunkSize(maxChunkSize)
  }
  if (maxHeaderSize != null) {
    this.setMaxHeaderSize(maxHeaderSize)
  }
  if (maxInitialLineLength != null) {
    this.setMaxInitialLineLength(maxInitialLineLength)
  }
  if (maxPoolSize != null) {
    this.setMaxPoolSize(maxPoolSize)
  }
  if (maxRedirects != null) {
    this.setMaxRedirects(maxRedirects)
  }
  if (maxWaitQueueSize != null) {
    this.setMaxWaitQueueSize(maxWaitQueueSize)
  }
  if (maxWebsocketFrameSize != null) {
    this.setMaxWebsocketFrameSize(maxWebsocketFrameSize)
  }
  if (maxWebsocketMessageSize != null) {
    this.setMaxWebsocketMessageSize(maxWebsocketMessageSize)
  }
  if (metricsName != null) {
    this.setMetricsName(metricsName)
  }
  if (openSslEngineOptions != null) {
    this.setOpenSslEngineOptions(openSslEngineOptions)
  }
  if (pemKeyCertOptions != null) {
    this.setPemKeyCertOptions(pemKeyCertOptions)
  }
  if (pemTrustOptions != null) {
    this.setPemTrustOptions(pemTrustOptions)
  }
  if (pfxKeyCertOptions != null) {
    this.setPfxKeyCertOptions(pfxKeyCertOptions)
  }
  if (pfxTrustOptions != null) {
    this.setPfxTrustOptions(pfxTrustOptions)
  }
  if (pipelining != null) {
    this.setPipelining(pipelining)
  }
  if (pipeliningLimit != null) {
    this.setPipeliningLimit(pipeliningLimit)
  }
  if (protocolVersion != null) {
    this.setProtocolVersion(protocolVersion)
  }
  if (proxyOptions != null) {
    this.setProxyOptions(proxyOptions)
  }
  if (pubSecKeys != null) {
    this.setPubSecKeys(pubSecKeys.toList())
  }
  if (receiveBufferSize != null) {
    this.setReceiveBufferSize(receiveBufferSize)
  }
  if (reuseAddress != null) {
    this.setReuseAddress(reuseAddress)
  }
  if (reusePort != null) {
    this.setReusePort(reusePort)
  }
  if (revocationPath != null) {
    this.setRevocationPath(revocationPath)
  }
  if (scopeSeparator != null) {
    this.setScopeSeparator(scopeSeparator)
  }
  if (sendBufferSize != null) {
    this.setSendBufferSize(sendBufferSize)
  }
  if (sendUnmaskedFrames != null) {
    this.setSendUnmaskedFrames(sendUnmaskedFrames)
  }
  if (site != null) {
    this.setSite(site)
  }
  if (soLinger != null) {
    this.setSoLinger(soLinger)
  }
  if (ssl != null) {
    this.setSsl(ssl)
  }
  if (tcpCork != null) {
    this.setTcpCork(tcpCork)
  }
  if (tcpFastOpen != null) {
    this.setTcpFastOpen(tcpFastOpen)
  }
  if (tcpKeepAlive != null) {
    this.setTcpKeepAlive(tcpKeepAlive)
  }
  if (tcpNoDelay != null) {
    this.setTcpNoDelay(tcpNoDelay)
  }
  if (tcpQuickAck != null) {
    this.setTcpQuickAck(tcpQuickAck)
  }
  if (tokenPath != null) {
    this.setTokenPath(tokenPath)
  }
  if (trafficClass != null) {
    this.setTrafficClass(trafficClass)
  }
  if (trustAll != null) {
    this.setTrustAll(trustAll)
  }
  if (trustStoreOptions != null) {
    this.setTrustStoreOptions(trustStoreOptions)
  }
  if (tryUseCompression != null) {
    this.setTryUseCompression(tryUseCompression)
  }
  if (useAlpn != null) {
    this.setUseAlpn(useAlpn)
  }
  if (useBasicAuthorizationHeader != null) {
    this.setUseBasicAuthorizationHeader(useBasicAuthorizationHeader)
  }
  if (usePooledBuffers != null) {
    this.setUsePooledBuffers(usePooledBuffers)
  }
  if (userAgent != null) {
    this.setUserAgent(userAgent)
  }
  if (userInfoParameters != null) {
    this.setUserInfoParameters(userInfoParameters)
  }
  if (userInfoPath != null) {
    this.setUserInfoPath(userInfoPath)
  }
  if (verifyHost != null) {
    this.setVerifyHost(verifyHost)
  }
}

