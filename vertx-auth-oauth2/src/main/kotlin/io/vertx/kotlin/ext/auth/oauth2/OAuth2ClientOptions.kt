package io.vertx.kotlin.ext.auth.oauth2

import io.vertx.ext.auth.oauth2.OAuth2ClientOptions
import io.vertx.core.http.HttpVersion

fun OAuth2ClientOptions(
        alpnVersions: List<HttpVersion>? = null,
    authorizationPath: String? = null,
    clientID: String? = null,
    clientSecret: String? = null,
    clientSecretParameterName: String? = null,
    connectTimeout: Int? = null,
    defaultHost: String? = null,
    defaultPort: Int? = null,
    headers: io.vertx.core.json.JsonObject? = null,
    http2ClearTextUpgrade: Boolean? = null,
    http2ConnectionWindowSize: Int? = null,
    http2MaxPoolSize: Int? = null,
    http2MultiplexingLimit: Int? = null,
    idleTimeout: Int? = null,
    initialSettings: io.vertx.core.http.Http2Settings? = null,
    jwtToken: Boolean? = null,
    keepAlive: Boolean? = null,
    localAddress: String? = null,
    logActivity: Boolean? = null,
    logoutPath: String? = null,
    maxChunkSize: Int? = null,
    maxPoolSize: Int? = null,
    maxWaitQueueSize: Int? = null,
    maxWebsocketFrameSize: Int? = null,
    metricsName: String? = null,
    pipelining: Boolean? = null,
    pipeliningLimit: Int? = null,
    protocolVersion: HttpVersion? = null,
    proxyOptions: io.vertx.core.net.ProxyOptions? = null,
    publicKey: String? = null,
    receiveBufferSize: Int? = null,
    reuseAddress: Boolean? = null,
    revocationPath: String? = null,
    sendBufferSize: Int? = null,
    site: String? = null,
    soLinger: Int? = null,
    ssl: Boolean? = null,
    tcpKeepAlive: Boolean? = null,
    tcpNoDelay: Boolean? = null,
    tokenPath: String? = null,
    trafficClass: Int? = null,
    trustAll: Boolean? = null,
    tryUseCompression: Boolean? = null,
    useAlpn: Boolean? = null,
    useBasicAuthorizationHeader: Boolean? = null,
    usePooledBuffers: Boolean? = null,
    userAgent: String? = null,
    userInfoPath: String? = null,
    verifyHost: Boolean? = null): OAuth2ClientOptions = io.vertx.ext.auth.oauth2.OAuth2ClientOptions().apply {

    if (alpnVersions != null) {
        this.alpnVersions = alpnVersions
    }

    if (authorizationPath != null) {
        this.authorizationPath = authorizationPath
    }

    if (clientID != null) {
        this.clientID = clientID
    }

    if (clientSecret != null) {
        this.clientSecret = clientSecret
    }

    if (clientSecretParameterName != null) {
        this.clientSecretParameterName = clientSecretParameterName
    }

    if (connectTimeout != null) {
        this.connectTimeout = connectTimeout
    }

    if (defaultHost != null) {
        this.defaultHost = defaultHost
    }

    if (defaultPort != null) {
        this.defaultPort = defaultPort
    }

    if (headers != null) {
        this.headers = headers
    }

    if (http2ClearTextUpgrade != null) {
        this.isHttp2ClearTextUpgrade = http2ClearTextUpgrade
    }

    if (http2ConnectionWindowSize != null) {
        this.http2ConnectionWindowSize = http2ConnectionWindowSize
    }

    if (http2MaxPoolSize != null) {
        this.http2MaxPoolSize = http2MaxPoolSize
    }

    if (http2MultiplexingLimit != null) {
        this.http2MultiplexingLimit = http2MultiplexingLimit
    }

    if (idleTimeout != null) {
        this.idleTimeout = idleTimeout
    }

    if (initialSettings != null) {
        this.initialSettings = initialSettings
    }

    if (jwtToken != null) {
        this.isJwtToken = jwtToken
    }

    if (keepAlive != null) {
        this.isKeepAlive = keepAlive
    }

    if (localAddress != null) {
        this.localAddress = localAddress
    }

    if (logActivity != null) {
        this.logActivity = logActivity
    }

    if (logoutPath != null) {
        this.logoutPath = logoutPath
    }

    if (maxChunkSize != null) {
        this.maxChunkSize = maxChunkSize
    }

    if (maxPoolSize != null) {
        this.maxPoolSize = maxPoolSize
    }

    if (maxWaitQueueSize != null) {
        this.maxWaitQueueSize = maxWaitQueueSize
    }

    if (maxWebsocketFrameSize != null) {
        this.maxWebsocketFrameSize = maxWebsocketFrameSize
    }

    if (metricsName != null) {
        this.metricsName = metricsName
    }

    if (pipelining != null) {
        this.isPipelining = pipelining
    }

    if (pipeliningLimit != null) {
        this.pipeliningLimit = pipeliningLimit
    }

    if (protocolVersion != null) {
        this.protocolVersion = protocolVersion
    }

    if (proxyOptions != null) {
        this.proxyOptions = proxyOptions
    }

    if (publicKey != null) {
        this.publicKey = publicKey
    }

    if (receiveBufferSize != null) {
        this.receiveBufferSize = receiveBufferSize
    }

    if (reuseAddress != null) {
        this.isReuseAddress = reuseAddress
    }

    if (revocationPath != null) {
        this.revocationPath = revocationPath
    }

    if (sendBufferSize != null) {
        this.sendBufferSize = sendBufferSize
    }

    if (site != null) {
        this.site = site
    }

    if (soLinger != null) {
        this.soLinger = soLinger
    }

    if (ssl != null) {
        this.isSsl = ssl
    }

    if (tcpKeepAlive != null) {
        this.isTcpKeepAlive = tcpKeepAlive
    }

    if (tcpNoDelay != null) {
        this.isTcpNoDelay = tcpNoDelay
    }

    if (tokenPath != null) {
        this.tokenPath = tokenPath
    }

    if (trafficClass != null) {
        this.trafficClass = trafficClass
    }

    if (trustAll != null) {
        this.isTrustAll = trustAll
    }

    if (tryUseCompression != null) {
        this.isTryUseCompression = tryUseCompression
    }

    if (useAlpn != null) {
        this.isUseAlpn = useAlpn
    }

    if (useBasicAuthorizationHeader != null) {
        this.isUseBasicAuthorizationHeader = useBasicAuthorizationHeader
    }

    if (usePooledBuffers != null) {
        this.isUsePooledBuffers = usePooledBuffers
    }

    if (userAgent != null) {
        this.userAgent = userAgent
    }

    if (userInfoPath != null) {
        this.userInfoPath = userInfoPath
    }

    if (verifyHost != null) {
        this.isVerifyHost = verifyHost
    }

}

