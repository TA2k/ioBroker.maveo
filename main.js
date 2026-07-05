"use strict";

/*
 * ioBroker.maveo — Adapter for the Marantec maveo (garage door) system.
 *
 * Two transports, one control layer:
 *
 *   1) Cloud (default when no boxIp is configured):
 *      - Cognito USER_PASSWORD_AUTH → idToken
 *      - GetId + GetCredentialsForIdentity → identityId (+ AWS creds for the
 *        optional IoT wake publish)
 *      - wss://remoteproxy.nymea.io → Authentication.Authenticate with the
 *        idToken → nymea JSON-RPC tunnel to the box
 *
 *   2) LAN (when boxIp is configured):
 *      - Direct nymea JSON-RPC to <boxIp>:<port> (2222 raw / 4444 WS)
 *      - Push-button authentication on first run (yellow button on the box),
 *        token stored in native.localToken
 *      - Same JSON-RPC surface as the cloud tunnel from that point on
 *
 * Constants verified by Ghidra-decompile of libmaveo-app_arm64-v8a.so
 * (see .references/*.md for details). Pool/client IDs and identity pool
 * change with region; see ENVIRONMENTS below.
 */

const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const WebSocket = require("ws");
const net = require("net");
const tls = require("tls");
const { v4: uuidv4 } = require("uuid");
const aws4 = require("aws4");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const Json2iob = require("json2iob");

const ENVIRONMENTS = {
  eu: {
    userPoolId: "eu-central-1_ozbW8rTAj",
    clientId: "34eruqhvvnniig5bccrre6s0ck",
    userPoolRegion: "eu-central-1",
    identityPoolId: "eu-central-1:b3ebe605-53c9-463e-8738-70ae01b042ee",
    identityRegion: "eu-central-1",
    apiHost: "eu-central-1.api-prod.marantec-cloud.de",
    apiRegion: "eu-central-1",
    iotHost: "eu-central-1.iot-prod.marantec-cloud.de",
    iotRegion: "eu-central-1",
  },
  us: {
    userPoolId: "us-west-2_me1sJlGXO",
    clientId: "34eruqhvvnniig5bccrre6s0ck",
    userPoolRegion: "us-west-2",
    identityPoolId: "us-west-2:91b51fae-6590-4452-9154-b5daf4ca745e",
    identityRegion: "us-west-2",
    apiHost: "us-west-2.api-prod.marantec-cloud.de",
    apiRegion: "us-west-2",
    iotHost: "us-west-2.iot-prod.marantec-cloud.de",
    iotRegion: "us-west-2",
  },
};

const REMOTE_PROXY_URL = "wss://remoteproxy.nymea.io";
const NAMESPACES = [
  "System", "JSONRPC", "Integrations", "Rules",
  "Logging", "Configuration", "Tags", "Scripts",
];

class Maveo extends utils.Adapter {
  constructor(options) {
    super({ ...options, name: "maveo" });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));

    this.session = {};
    this.env = ENVIRONMENTS.eu;

    // shared state across both transports
    this.things = {};
    this.thingClasses = {};
    this.stateTypes = {};
    this.actionTypesByThing = {};

    // json-rpc request tracking
    this.rpcRequestId = 100;
    this.rpcRequests = {};   // requestId → { resolve, reject, timeout }
    this.msgBuffer = "";

    // transports (only one is active at a time)
    this.ws = null;          // Cloud: WebSocket to remoteproxy
    this.lanSocket = null;   // LAN: net or tls socket
    this.mode = "cloud";     // "cloud" | "lan"

    this.requestClient = axios.create({ timeout: 30000 });
    this.json2iob = new Json2iob(this);
    this.reconnectTimer = null;
    this.reconnectDelay = 5000;
    this.refreshTokenTimer = null;
    this.wsIdleTimer = null;
    this.destroyed = false;
  }

  async onReady() {
    await this.setStateAsync("info.connection", false, true);

    const region = (this.config.region || "eu").toLowerCase();
    if (!ENVIRONMENTS[region]) {
      this.log.error(`Unknown region "${region}", falling back to "eu".`);
    }
    this.env = ENVIRONMENTS[region] || ENVIRONMENTS.eu;

    this.subscribeStates("*");

    const boxIp = (this.config.boxIp || "").trim();
    if (boxIp) {
      this.mode = "lan";
      this.log.info(`LAN mode: connecting directly to maveo box at ${boxIp}.`);
      this.connectLan();
      return;
    }

    // Cloud mode requires credentials.
    if (!this.config.username || !this.config.password) {
      this.log.error("Missing username/password and no boxIp set — configure either the maveo app credentials (cloud mode) or a box IP (LAN mode).");
      return;
    }

    this.mode = "cloud";
    try {
      await this.loginWithCognito();
    } catch (err) {
      this.log.error("Login failed: " + this.errorText(err));
      return;
    }

    this.refreshTokenTimer = setInterval(() => {
      this.refreshCognitoSession().catch((err) =>
        this.log.error("Refresh failed: " + this.errorText(err))
      );
    }, 55 * 60 * 1000);

    this.wakeAndConnect();
  }

  // ============================================================ Cognito

  loginWithCognito() {
    return new Promise((resolve, reject) => {
      const authData = new AmazonCognitoIdentity.AuthenticationDetails({
        Username: this.config.username,
        Password: this.config.password,
      });
      const userPool = new AmazonCognitoIdentity.CognitoUserPool({
        UserPoolId: this.env.userPoolId,
        ClientId: this.env.clientId,
      });
      this.cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: this.config.username,
        Pool: userPool,
      });
      // The marantec cloud client only allows USER_PASSWORD_AUTH; SRP is disabled.
      this.cognitoUser.setAuthenticationFlowType("USER_PASSWORD_AUTH");

      this.cognitoUser.authenticateUser(authData, {
        onSuccess: async (result) => {
          try {
            this.session.idToken = result.getIdToken().getJwtToken();
            this.session.refreshToken = result.getRefreshToken().getToken();
            this.session.accessToken = result.getAccessToken().getJwtToken();
            await this.fetchAwsCredentials();
            await this.setStateAsync("info.connection", true, true);
            this.log.info(`Logged in to Marantec cloud (${this.config.region || "eu"}).`);
            resolve(undefined);
          } catch (err) {
            reject(err);
          }
        },
        onFailure: (err) => reject(err),
        newPasswordRequired: () => reject(new Error("NEW_PASSWORD_REQUIRED — not supported")),
      });
    });
  }

  async refreshCognitoSession() {
    if (!this.cognitoUser || !this.session.refreshToken) return;
    const cognitoUser = this.cognitoUser;
    this.log.debug("Refreshing Cognito session");
    await new Promise((resolve, reject) => {
      const token = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: this.session.refreshToken });
      cognitoUser.refreshSession(token, async (err, result) => {
        if (err) return reject(err);
        try {
          this.session.idToken = result.getIdToken().getJwtToken();
          this.session.refreshToken = result.getRefreshToken().getToken();
          this.session.accessToken = result.getAccessToken().getJwtToken();
          await this.fetchAwsCredentials();
          resolve(undefined);
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  async fetchAwsCredentials() {
    const loginsKey = `cognito-idp.${this.env.userPoolRegion}.amazonaws.com/${this.env.userPoolId}`;
    const endpoint = `https://cognito-identity.${this.env.identityRegion}.amazonaws.com/`;
    const logins = { [loginsKey]: this.session.idToken };

    const getId = await this.requestClient({
      method: "post",
      url: endpoint,
      headers: {
        "Content-Type": "application/x-amz-json-1.0",
        "X-Amz-Target": "AWSCognitoIdentityService.GetId",
      },
      data: { IdentityPoolId: this.env.identityPoolId, Logins: logins },
    });
    this.session.identityId = getId.data && getId.data.IdentityId;
    if (!this.session.identityId) throw new Error("Cognito GetId did not return an IdentityId");

    const res = await this.requestClient({
      method: "post",
      url: endpoint,
      headers: {
        "Content-Type": "application/x-amz-json-1.0",
        "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
      },
      data: { IdentityId: this.session.identityId, Logins: logins },
    });
    this.session.credentials = res.data.Credentials;
    this.log.debug("AWS credentials refreshed, expiring " + this.session.credentials.Expiration);
  }

  // ============================================================ IoT wake (cloud)

  async publishWake() {
    const topic = this.config.wakeTopic;
    if (!topic) {
      this.log.debug("No wakeTopic configured — skipping the IoT wake publish.");
      return;
    }
    const path = "/topics/" + topic.split("/").map(encodeURIComponent).join("%2F") + "?qos=1";
    const body = JSON.stringify({ nonce: this.nonce, timestamp: this.nonce, token: this.session.idToken });
    const signed = this.signAws(
      { host: this.env.iotHost, method: "POST", path, service: "iotdata", region: this.env.iotRegion, body },
      { "content-type": "application/json" }
    );
    try {
      await this.requestClient({
        method: "POST",
        url: `https://${this.env.iotHost}${path}`,
        headers: signed.headers,
        data: body,
      });
      this.log.debug("Wake publish sent.");
    } catch (err) {
      this.log.warn("Wake publish failed: " + this.errorText(err));
    }
  }

  signAws({ host, method, path, service, region, body }, extra) {
    /** @type {{ host: string, method: string, path: string, service: string, region: string, body?: string, headers: Record<string, string> }} */
    const req = { host, method, path, service, region, headers: { ...(extra || {}) } };
    if (body != null) req.body = body;
    aws4.sign(req, {
      accessKeyId: this.session.credentials.AccessKeyId,
      secretAccessKey: this.session.credentials.SecretKey,
      sessionToken: this.session.credentials.SessionToken,
    });
    return req;
  }

  // ============================================================ Cloud transport (WSS)

  wakeAndConnect() {
    if (this.destroyed) return;
    this.nonce = "{" + uuidv4() + "}";
    Promise.resolve()
      .then(() => this.publishWake())
      .then(() => this.connectTunnel())
      .catch((err) => {
        this.log.error("WebSocket setup failed: " + this.errorText(err));
        this.scheduleReconnect();
      });
  }

  connectTunnel() {
    if (this.destroyed) return;
    this.rejectRpcRequests("tunnel reconnect");
    if (this.ws) {
      try { this.ws.removeAllListeners(); this.ws.close(); } catch { /* ignore */ }
    }
    this.msgBuffer = "";
    this.log.debug("Connecting tunnel: " + REMOTE_PROXY_URL);
    this.ws = new WebSocket(REMOTE_PROXY_URL, { perMessageDeflate: false });

    this.ws.on("open", () => {
      this.log.info("Tunnel connected.");
      this.reconnectDelay = 5000;
      this.armIdleTimer();
      this.sendRaw({ id: 0, method: "RemoteProxy.Hello" });
      this.sendRaw({
        id: 0,
        method: "Authentication.Authenticate",
        params: {
          name: "iobroker-maveo",
          nonce: this.nonce,
          token: this.session.idToken,
          uuid: uuidv4(),
        },
      });
    });

    this.ws.on("message", (data, isBinary) => {
      this.armIdleTimer();
      this.handleMessages(isBinary ? data : data.toString());
    });

    this.ws.on("close", () => {
      this.log.info("Tunnel closed.");
      this.rejectRpcRequests("tunnel closed");
      this.setStateAsync("info.connection", false, true).catch(() => {});
      this.scheduleReconnect();
    });

    this.ws.on("error", (err) => this.log.error("Tunnel error: " + this.errorText(err)));
  }

  // ============================================================ LAN transport (TCP/TLS)

  connectLan() {
    if (this.destroyed) return;
    this.rejectRpcRequests("lan reconnect");
    if (this.lanSocket) {
      try { this.lanSocket.removeAllListeners(); this.lanSocket.destroy(); } catch { /* ignore */ }
      this.lanSocket = null;
    }
    this.msgBuffer = "";

    const host = (this.config.boxIp || "").trim();
    const port = Number(this.config.boxPort) || 2222;
    const useTls = this.config.boxTls !== false; // default true, nymea:core listens on SSL by default

    this.log.debug(`LAN connect: host=${host} port=${port} tls=${useTls} tokenStored=${!!this.config.localToken}`);

    const onConnect = () => {
      this.log.info(`LAN socket connected to ${host}:${port} (${useTls ? "TLS" : "plain"}).`);
      this.reconnectDelay = 5000;
      this.startLanHandshake().catch((err) => {
        this.log.error("LAN handshake failed: " + this.errorText(err));
        try { this.lanSocket && this.lanSocket.destroy(); } catch { /* ignore */ }
      });
    };
    const onData = (chunk) => {
      const text = chunk.toString("utf8");
      if (this.log.level === "debug" || this.log.level === "silly") {
        // Keep the log line short so the transcript stays readable, but the
        // full payload is available on the debug channel when investigating
        // LAN handshake issues.
        this.log.debug(`LAN <-- ${text.length} bytes: ${text.slice(0, 400).replace(/\n/g, "\\n")}${text.length > 400 ? "…" : ""}`);
      }
      this.handleMessages(text);
    };
    const onClose = (hadError) => {
      this.log.info(`LAN socket closed${hadError ? " (with error)" : ""}.`);
      this.rejectRpcRequests("lan closed");
      this.setStateAsync("info.connection", false, true).catch(() => {});
      this.scheduleReconnect();
    };
    const onError = (err) => this.log.error("LAN socket error: " + this.errorText(err));

    if (useTls) {
      // The maveo box ships a self-signed certificate. Skip verification.
      this.lanSocket = tls.connect({ host, port, rejectUnauthorized: false }, onConnect);
      this.lanSocket.on("secureConnect", () => {
        const sock = /** @type {tls.TLSSocket} */ (this.lanSocket);
        try {
          const cert = sock && sock.getPeerCertificate && sock.getPeerCertificate();
          const cipher = sock && sock.getCipher && sock.getCipher();
          const proto = sock && sock.getProtocol && sock.getProtocol();
          this.log.debug(`LAN TLS ready: proto=${proto} cipher=${cipher && cipher.name} peer=${cert && cert.subject && cert.subject.CN}`);
        } catch { /* ignore */ }
      });
    } else {
      this.lanSocket = net.createConnection({ host, port }, onConnect);
    }
    this.lanSocket.on("data", onData);
    this.lanSocket.on("close", onClose);
    this.lanSocket.on("error", onError);
    this.lanSocket.setTimeout(30000, () => {
      this.log.warn(`LAN socket idle for 30 s — closing and letting reconnect handle it.`);
      try { this.lanSocket && this.lanSocket.destroy(new Error("LAN idle timeout")); } catch { /* ignore */ }
    });
  }

  async startLanHandshake() {
    // JSONRPC.Hello establishes protocol version and tells us whether we
    // need to authenticate at all.
    this.log.debug("LAN handshake: sending JSONRPC.Hello");
    const hello = await this.sendAndAwait({ method: "JSONRPC.Hello", params: { locale: "de_DE" } }, true);
    const helloParams = hello && hello.params || {};
    const needsAuth = helloParams.authenticationRequired !== false;
    this.log.info(
      `LAN Hello reply: server=${helloParams.server || "?"} version=${helloParams.version || "?"} ` +
      `protocol=${helloParams.protocol || "?"} authRequired=${needsAuth} ` +
      `pushButton=${helloParams.pushButtonAuthAvailable !== false} ` +
      `initialSetup=${!!helloParams.initialSetupRequired}`
    );
    this.log.debug("LAN Hello full reply: " + JSON.stringify(helloParams));

    if (helloParams.initialSetupRequired) {
      throw new Error("Box reports initialSetupRequired=true — set the box up in the maveo app first, then try again.");
    }

    if (needsAuth) {
      let token = this.config.localToken || "";
      if (!token) {
        if (helloParams.pushButtonAuthAvailable === false) {
          throw new Error("Box requires authentication but does not offer push-button auth.");
        }
        this.log.warn("No token yet — starting push-button auth. Press the yellow button on the maveo box within 60 seconds.");
        try {
          token = await this.pushButtonAuth();
        } catch (err) {
          this.log.error("Push-button auth failed: " + this.errorText(err));
          throw err;
        }
        // Persist token so the next start is silent.
        try {
          await this.updateConfig({ localToken: token });
          this.config.localToken = token;
          this.log.info("Push-button auth succeeded, token persisted to instance config.");
        } catch (err) {
          this.log.warn("Push-button auth succeeded but persisting token to config failed: " + this.errorText(err));
        }
      } else {
        this.log.debug("Reusing stored localToken (length=" + token.length + ").");
      }
      this.rpcToken = token;
    } else {
      this.log.info("Box does not require authentication.");
      this.rpcToken = null;
    }

    this.log.debug("LAN handshake: enabling notifications");
    await this.sendAndAwait({
      method: "JSONRPC.SetNotificationStatus",
      // The nymea reference implementation (HA custom_component maveo_box.py)
      // sends just { enabled: true }. Some nymea versions accept a namespaces
      // filter, but the boolean form is the compatible baseline.
      params: { enabled: true },
    });

    this.log.debug("LAN handshake: initTopology");
    await this.initTopology();
    await this.setStateAsync("info.connection", true, true);
    this.log.info("LAN handshake complete.");
  }

  pushButtonAuth() {
    // Two-phase handshake:
    //   1. RequestPushButtonAuth returns { transactionId }
    //   2. Box emits notification JSONRPC.PushButtonAuthFinished with the
    //      same transactionId once the user presses the button.
    // We register the pending expectation BEFORE sending the request so a
    // very fast notification (or one already buffered) is not lost, and we
    // route the notification through dispatchMessage rather than a raw-line
    // sniffer.
    return new Promise((resolve, reject) => {
      /** @type {{ transactionId: number, earlyNotifications: any[], settled: boolean, resolve: (t: string) => void, reject: (e: Error) => void, settle: (fn: () => void) => void }} */
      const pending = /** @type {any} */ ({
        transactionId: -1,             // filled in when the reply arrives
        earlyNotifications: [],        // params received before we know the txId
        settled: false,
      });
      this.pendingPushButton = pending;

      const settle = (/** @type {() => void} */ fn) => {
        if (pending.settled) return;
        pending.settled = true;
        if (this.pushButtonTimeout) {
          clearTimeout(this.pushButtonTimeout);
          this.pushButtonTimeout = null;
        }
        this.pendingPushButton = null;
        fn();
      };

      this.pushButtonTimeout = setTimeout(() => {
        settle(() => reject(new Error("Push-button auth timed out — no button press within 60 s.")));
      }, 60000);

      this.sendAndAwait({
        method: "JSONRPC.RequestPushButtonAuth",
        params: { deviceName: "iobroker-maveo" },
      }, true).then((reply) => {
        const txId = reply && reply.params && reply.params.transactionId;
        if (typeof txId !== "number") {
          settle(() => reject(new Error("RequestPushButtonAuth: no transactionId in reply: " + JSON.stringify(reply))));
          return;
        }
        pending.transactionId = txId;
        this.log.info(`Push-button auth started (txId=${txId}). WAITING FOR BUTTON PRESS on the maveo box.`);
        // Drain any notifications that arrived before we knew the txId.
        /** @type {any[]} */
        const early = pending.earlyNotifications.splice(0);
        if (early.length) this.log.debug(`Draining ${early.length} early push-button notification(s).`);
        for (const params of early) this.deliverPushButton(params);
      }).catch((err) => settle(() => reject(err)));

      pending.resolve = resolve;
      pending.reject = reject;
      pending.settle = settle;
    });
  }

  /** @param {any} params */
  deliverPushButton(params) {
    const pending = this.pendingPushButton;
    if (!pending || pending.settled) return;
    if (pending.transactionId < 0) {
      // Reply hasn't arrived yet — buffer for later matching.
      pending.earlyNotifications.push(params);
      return;
    }
    if (params.transactionId !== pending.transactionId) return;
    if (params.success && params.token) {
      pending.settle(() => pending.resolve(params.token));
    } else {
      pending.settle(() => pending.reject(new Error("Push-button auth failed: " + JSON.stringify(params))));
    }
  }

  // ============================================================ Connection management

  scheduleReconnect() {
    if (this.destroyed) return;
    if (this.reconnectTimer) return;
    const delay = Math.min(this.reconnectDelay, 5 * 60 * 1000);
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      this.reconnectDelay = Math.min(delay * 2, 5 * 60 * 1000);
      if (this.mode === "lan") {
        this.connectLan();
        return;
      }
      // Cloud reconnect: refresh the Cognito session if the current
      // credentials look stale. The idToken TTL is 60 min and AWS creds
      // ~1 h too, so anything approaching that age is worth refreshing
      // before we try to hit the wake endpoint and the remote proxy.
      try {
        if (this.cognitoUser && this.session.refreshToken) {
          await this.refreshCognitoSession();
        }
      } catch (err) {
        this.log.warn("Refresh before reconnect failed: " + this.errorText(err));
      }
      this.wakeAndConnect();
    }, delay);
  }

  armIdleTimer() {
    if (this.mode !== "cloud") return;
    if (this.wsIdleTimer) clearTimeout(this.wsIdleTimer);
    this.wsIdleTimer = setTimeout(() => {
      this.log.info("Tunnel idle for 11 min — reconnecting.");
      try { this.ws && this.ws.close(); } catch { /* ignore */ }
    }, 11 * 60 * 1000);
  }

  // ============================================================ JSON-RPC framing

  handleMessages(chunk) {
    this.msgBuffer += chunk;
    let start = 0;
    while (start < this.msgBuffer.length) {
      const nl = this.msgBuffer.indexOf("\n", start);
      const end = nl === -1 ? this.msgBuffer.length : nl;
      const segment = this.msgBuffer.slice(start, end).trim();
      if (!segment) { start = end + 1; continue; }
      let parsed;
      try {
        parsed = JSON.parse(segment);
      } catch {
        if (nl === -1) {
          this.msgBuffer = this.msgBuffer.slice(start);
          return;
        }
        this.log.debug("Skipping unparseable segment: " + segment.slice(0, 80));
        start = end + 1;
        continue;
      }
      // Route JSONRPC.PushButtonAuthFinished via dispatchMessage so the
      // pending-auth handler works on the parsed object with proper
      // txId matching (see deliverPushButton).
      this.dispatchMessage(parsed).catch((err) =>
        this.log.error("Message handler crashed: " + this.errorText(err))
      );
      start = end + 1;
    }
    this.msgBuffer = "";
  }

  async dispatchMessage(msg) {
    if (msg.id != null && this.rpcRequests[msg.id]) {
      const req = this.rpcRequests[msg.id];
      delete this.rpcRequests[msg.id];
      clearTimeout(req.timeout);
      if (msg.status === "error") {
        this.log.debug(`<-- id=${msg.id} ERROR: ${JSON.stringify(msg.error || msg.params || msg).slice(0, 400)}`);
        req.reject(new Error("Nymea error reply for id " + msg.id + ": " + JSON.stringify(msg.error || msg.params || msg)));
      } else {
        this.log.debug(`<-- id=${msg.id} OK`);
        req.resolve(msg);
      }
      return;
    }

    if (msg.status === "error") {
      this.log.error("Reply error: " + JSON.stringify(msg));
      return;
    }

    if (msg.notification) {
      this.log.debug(`<-- notification: ${msg.notification}`);
    }

    // Cloud only: after Authenticate the proxy notifies us to start
    // talking to nymea:core.
    if (msg.notification === "RemoteProxy.TunnelEstablished") {
      this.log.info("Nymea tunnel established.");
      await this.initTopology();
      await this.setStateAsync("info.connection", true, true);
      return;
    }

    if (msg.notification === "JSONRPC.PushButtonAuthFinished" && msg.params) {
      this.log.info(`Push-button notification received: success=${msg.params.success} txId=${msg.params.transactionId}`);
      this.deliverPushButton(msg.params);
      return;
    }

    if (msg.notification === "Integrations.StateChanged" && msg.params) {
      await this.applyStateChange(msg.params);
      return;
    }
  }

  async initTopology() {
    // Emitted directly after transport-level auth; identical for cloud & LAN.
    if (this.mode === "cloud") {
      // Cloud path uses the nymea proxy JSONRPC.Hello with a locale param.
      this.sendRaw({ id: 1, method: "JSONRPC.Hello", params: { locale: "de_DE" }, token: null });
      this.sendRaw({
        id: 2,
        method: "JSONRPC.SetNotificationStatus",
        params: { namespaces: NAMESPACES },
        token: null,
      });
      await this.sendAndAwait({ method: "JSONRPC.IsCloudConnected", token: null });
    }
    const classes = await this.sendAndAwait({ method: "Integrations.GetThingClasses" });
    this.ingestThingClasses(classes && classes.params);
    this.log.info(`Ingested ${Object.keys(this.thingClasses).length} thing classes, ${Object.keys(this.stateTypes).length} state types.`);
    const things = await this.sendAndAwait({ method: "Integrations.GetThings" });
    const list = things && things.params && Array.isArray(things.params.things) ? things.params.things : [];
    this.log.info(`GetThings returned ${list.length} thing(s).`);
    for (const thing of list) {
      this.log.debug(`  thing id=${thing.id} name="${thing.name}" thingClassId=${thing.thingClassId} setupComplete=${thing.setupComplete}`);
    }
    await this.ingestThings(things && things.params);

    if (list.length === 0) {
      if (this.mode === "cloud") {
        this.log.warn([
          "The maveo cloud tunnel is up, but Integrations.GetThings returned no devices.",
          "This usually means your box was added 'only locally' in the maveo app and is",
          "therefore not registered against your Cognito account. You have two options:",
          "  1) Open the maveo app and re-onboard the box via Bluetooth so it gets linked",
          "     to your account (the app sends SetCognitoId + RegisterDeviceCognitoId over BLE).",
          "  2) Switch this adapter to LAN mode: set 'boxIp' in the adapter settings, restart",
          "     the adapter, and press the yellow button on the maveo box when prompted.",
        ].join("\n"));
      } else {
        this.log.warn("Box returned no things over LAN. Check that the box has been set up (device pairing done in the maveo app).");
      }
    }
  }

  rejectRpcRequests(reason) {
    for (const [id, req] of Object.entries(this.rpcRequests)) {
      clearTimeout(req.timeout);
      req.reject(new Error(reason));
      delete this.rpcRequests[id];
    }
  }

  // ============================================================ Transport-agnostic send

  sendRaw(payload) {
    const line = JSON.stringify(payload) + "\n";
    // Do not log token=<jwt> at info level; strip it for debug.
    const scrub = { ...payload };
    if (scrub.token) scrub.token = "<hidden>";
    if (scrub.params && scrub.params.token) scrub.params = { ...scrub.params, token: "<hidden>" };
    this.log.debug(`--> ${JSON.stringify(scrub).slice(0, 400)}`);
    if (this.mode === "cloud") {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        this.log.debug("WS not open, dropping " + payload.method);
        return;
      }
      this.ws.send(line);
    } else {
      if (!this.lanSocket || this.lanSocket.destroyed) {
        this.log.debug("LAN socket not open, dropping " + payload.method);
        return;
      }
      this.lanSocket.write(line);
    }
  }

  sendAndAwait(payload, isHandshake) {
    return new Promise((resolve, reject) => {
      const id = this.rpcRequestId++;
      const timeout = setTimeout(() => {
        if (this.rpcRequests[id]) {
          delete this.rpcRequests[id];
          this.log.warn(`Nymea call timed out: ${payload.method} (id=${id})`);
          reject(new Error("Nymea call timed out: " + payload.method));
        }
      }, 30000);
      this.rpcRequests[id] = { resolve, reject, timeout };
      const out = { ...payload, id };
      // Cloud calls always carry token: null (the tunnel already authenticated);
      // LAN calls carry the box token once handshake is past.
      if (this.mode === "cloud") {
        if (out.token === undefined) out.token = null;
      } else if (!isHandshake && this.rpcToken) {
        out.token = this.rpcToken;
      }
      this.sendRaw(out);
    });
  }

  // ============================================================ Ingest

  ingestThingClasses(params) {
    if (!params || !Array.isArray(params.thingClasses)) return;
    for (const tc of params.thingClasses) {
      const stateMap = {};
      for (const st of tc.stateTypes || []) {
        stateMap[st.id] = st;
        this.stateTypes[st.id] = st;
      }
      tc.stateTypes = stateMap;
      const actionMap = {};
      for (const at of tc.actionTypes || []) actionMap[at.id] = at;
      tc.actionTypes = actionMap;
      this.thingClasses[tc.id] = tc;
    }
  }

  async ingestThings(params) {
    if (!params || !Array.isArray(params.things)) return;
    for (const thing of params.things) {
      const stateMap = {};
      for (const st of thing.states || []) stateMap[st.stateTypeId] = st;
      thing.states = stateMap;
      this.things[thing.id] = thing;
      await this.createThingObjects(thing);
    }
  }

  async createThingObjects(thing) {
    const id = thing.id;
    await this.setObjectNotExistsAsync(id, {
      type: "device",
      common: { name: thing.name || id },
      native: {},
    });
    await this.setObjectNotExistsAsync(id + ".general", { type: "channel", common: { name: "General Information" }, native: {} });
    await this.setObjectNotExistsAsync(id + ".remote", { type: "channel", common: { name: "Remote Controls" }, native: {} });
    await this.json2iob.parse(id + ".general", {
      name: thing.name,
      thingClassId: thing.thingClassId,
      setupComplete: thing.setupComplete,
      params: thing.params,
    }, { channelName: "General Information" });

    const tc = this.thingClasses[thing.thingClassId];
    const actionTypes = tc ? tc.actionTypes || {} : {};
    const mapForThing = {};
    for (const at of Object.values(actionTypes)) {
      const command = (at.name || at.displayName || at.id).replace(/[^A-Za-z0-9_-]/g, "_");
      mapForThing[command] = at.id;
      await this.setObjectNotExistsAsync(id + ".remote." + command, {
        type: "state",
        common: {
          name: at.displayName || command,
          role: "button",
          type: "boolean",
          read: true,
          write: true,
          def: false,
        },
        native: { actionTypeId: at.id, thingId: id },
      });
    }
    this.actionTypesByThing[id] = mapForThing;

    const stateTypes = tc ? tc.stateTypes || {} : {};
    for (const s of Object.values(thing.states || {})) {
      const stateType = stateTypes[s.stateTypeId] || this.stateTypes[s.stateTypeId];
      if (!stateType) continue;
      await this.upsertStateObject(id, stateType);
      await this.setStateAsync(id + "." + stateType.id, {
        val: this.coerceStateValue(stateType, s.value),
        ack: true,
      });
    }
  }

  async applyStateChange(params) {
    const thingId = params.thingId;
    const stateType = this.stateTypes[params.stateTypeId];
    if (!thingId || !stateType) {
      this.log.debug(`StateChanged for unknown thing/stateType: thingId=${thingId} stateTypeId=${params.stateTypeId}`);
      return;
    }
    const name = stateType.displayName || stateType.name || stateType.id;
    this.log.debug(`StateChanged ${thingId}.${name} = ${JSON.stringify(params.value)}`);
    await this.setObjectNotExistsAsync(thingId, { type: "device", common: { name: thingId }, native: {} });
    await this.upsertStateObject(thingId, stateType);
    await this.setStateAsync(thingId + "." + stateType.id, {
      val: this.coerceStateValue(stateType, params.value),
      ack: true,
    });
  }

  async upsertStateObject(thingId, stateType) {
    const unit = stateType.unit && stateType.unit !== "UnitNone"
      ? stateType.unit.replace("Unit", "")
      : undefined;
    await this.setObjectNotExistsAsync(thingId + "." + stateType.id, {
      type: "state",
      common: {
        name: stateType.displayName || stateType.name || stateType.id,
        type: this.mapType(stateType.type),
        role: stateType.unit === "UnitUnixTime" ? "date" : "value",
        read: true,
        write: false,
        unit,
      },
      native: { stateTypeId: stateType.id },
    });
  }

  coerceStateValue(stateType, value) {
    if (stateType.unit === "UnitUnixTime" && typeof value === "number") return value * 1000;
    return value;
  }

  mapType(nymeaType) {
    switch (nymeaType) {
      case "Bool": return "boolean";
      case "Int":
      case "Uint":
      case "Double":
        return "number";
      case "String":
      case "Color":
      case "Time":
      case "QVariantMap":
        return "string";
      default: return "mixed";
    }
  }

  // ============================================================ Control

  async onStateChange(id, state) {
    if (!state || state.ack) return;
    const parts = id.split(".");
    if (parts.length < 5 || parts[parts.length - 2] !== "remote") return;
    const thingId = parts[parts.length - 3];
    const command = parts[parts.length - 1];
    const actionTypeId = (this.actionTypesByThing[thingId] || {})[command];
    if (!actionTypeId) {
      this.log.warn(`No actionType for ${thingId}.remote.${command}`);
      return;
    }
    this.log.info(`Sending ExecuteAction: thingId=${thingId} action=${command} (${actionTypeId})`);
    try {
      const reply = await this.sendAndAwait({
        method: "Integrations.ExecuteAction",
        params: { thingId, actionTypeId },
      });
      this.log.debug("ExecuteAction reply: " + JSON.stringify(reply));
    } catch (err) {
      this.log.error("ExecuteAction failed: " + this.errorText(err));
    }
  }

  // ============================================================ Misc

  errorText(err) {
    if (!err) return "unknown";
    if (err.response) return `${err.message} — ${JSON.stringify(err.response.data).slice(0, 300)}`;
    return err.stack || err.message || String(err);
  }

  onUnload(callback) {
    try {
      this.destroyed = true;
      this.setState("info.connection", false, true);
      if (this.refreshTokenTimer) clearInterval(this.refreshTokenTimer);
      if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
      if (this.wsIdleTimer) clearTimeout(this.wsIdleTimer);
      if (this.pushButtonTimeout) clearTimeout(this.pushButtonTimeout);
      // Fail any pending push-button auth so its promise consumer sees the shutdown.
      const pending = this.pendingPushButton;
      if (pending && !pending.settled) {
        try { pending.settle(() => pending.reject(new Error("adapter unload"))); } catch { /* ignore */ }
      }
      this.rejectRpcRequests("adapter unload");
      if (this.ws) {
        try { this.ws.removeAllListeners(); this.ws.close(); } catch { /* ignore */ }
      }
      if (this.lanSocket) {
        try { this.lanSocket.removeAllListeners(); this.lanSocket.destroy(); } catch { /* ignore */ }
      }
      callback();
    } catch {
      callback();
    }
  }
}

if (require.main !== module) {
  module.exports = (options) => new Maveo(options);
} else {
  new Maveo();
}
