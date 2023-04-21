"use strict";

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const aws4 = require("aws4");
const Json2iob = require("./lib/json2iob");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");

class Maveo extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: "maveo",
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));

    this.session = {};
    this.createsStates = {};
    this.currentMessage = "";
    this.requestClient = axios.create();
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.json2iob = new Json2iob(this);
    this.deviceArray = [];
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState("info.connection", false, true);
    if (this.config.interval < 0.5) {
      this.log.info("Set interval to minimum 0.5");
      this.config.interval = 0.5;
    }

    await this.login();

    if (this.session.idToken) {
      await this.getDeviceList();
      await this.connectToWS();

      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, 3500 * 1000);
    }
  }
  async login() {
    return new Promise((resolve, reject) => {
      const authenticationData = {
        Username: this.config.username,
        Password: this.config.password,
      };
      const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
      const poolData = {
        UserPoolId: "eu-central-1_ozbW8rTAj",
        ClientId: "34eruqhvvnniig5bccrre6s0ck",
      };
      const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
      const userData = {
        Username: this.config.username,
        Pool: userPool,
      };
      this.cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
      this.cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: async (result) => {
          this.log.debug(JSON.stringify(result));
          this.session.idToken = result.idToken.jwtToken;
          this.session.refreshToken = result.refreshToken.token;

          await this.requestClient({
            method: "post",
            url: "https://cognito-identity.eu-west-1.amazonaws.com/?Action=GetCredentialsForIdentity&Version=2016-06-30",
            headers: {
              "Content-Type": "application/x-amz-json-1.0",
              Host: "cognito-identity.eu-west-1.amazonaws.com",
              "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
              Connection: "Keep-Alive",
              "Accept-Language": "de-DE,en,*",
              "User-Agent": "Mozilla/5.0",
            },
            data:
              '{"IdentityId":"eu-central-1:62073914-b583-49d9-9b06-694a9d1e5762","Logins":{"cognito-idp.eu-west-1.amazonaws.com/eu-central-1_ozbW8rTAj":"' +
              this.session.idToken +
              '"}}',
          })
            .then((res) => {
              this.log.debug(JSON.stringify(res.data));
              this.session.Credentials = res.data.Credentials;

              return res.data;
            })
            .catch((error) => {
              this.log.error(error);
              if (error.response) {
                this.log.error(JSON.stringify(error.response.data));
              }
            });
          this.setState("info.connection", true, true);
          resolve(null);
        },

        onFailure: (err) => {
          this.log.error(err.message || JSON.stringify(err));
          resolve(null);
        },
      });
    });
  }
  async getDeviceList() {
    await this.requestClient({
      method: "get",
      url: "https://api-cloud.nymea.io/users/devices",
      headers: {
        "accept-charset": "UTF-8, ISO-8859-1",
        "x-api-idtoken": this.session.idToken,
        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-A805F Build/PPR1.180610.011)",
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));

        for (const device of res.data.devices) {
          const id = device.deviceId;
          this.deviceArray.push(id);
          await this.setObjectNotExistsAsync(id, {
            type: "device",
            common: {
              name: device.name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + ".remote", {
            type: "channel",
            common: {
              name: "Remote Controls",
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + ".general", {
            type: "channel",
            common: {
              name: "General Information",
            },
            native: {},
          });

          const remoteArray = [];
          remoteArray.forEach((remote) => {
            this.setObjectNotExists(id + ".remote." + remote.command, {
              type: "state",
              common: {
                name: remote.name || "",
                type: remote.type || "boolean",
                role: remote.role || "boolean",
                write: true,
                read: true,
              },
              native: {},
            });
          });
          this.json2iob.parse(id + ".general", device);
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async connectToWS() {
    if (this.ws) {
      this.ws.close();
    }
    this.nonce = "{" + uuidv4() + "}";
    const body = JSON.stringify({
      nonce: this.nonce,
      timestamp: this.nonce,
      token: this.session.idToken,
    });
    const headers = {
      "content-type": "application/json",
      "X-Amz-Date": this.amzDate(),
      "x-amz-security-token": this.session.Credentials.SessionToken,
      "User-Agent": "Mozilla/5.0",
    };
    const signed = aws4.sign(
      {
        host: "a27q7a2x15m8h3-ats.iot.eu-west-1.amazonaws.com",
        path: "/topics/90613aac-404e-47ea-8775-217db52a0b34%2Feu-west-1%3A0dee80a0-cc10-4e01-9f84-34ca36d06cbb%2Fproxy?qos=1",
        service: "iotdata",
        method: "POST",
        region: "eu-west-1",
        headers: headers,
        body: body,
      },
      { accessKeyId: this.session.Credentials.AccessKeyId, secretAccessKey: this.session.Credentials.SecretKey }
    );
    headers["Authorization"] = signed.headers["Authorization"];
    await this.requestClient({
      method: "post",
      url: "https://a27q7a2x15m8h3-ats.iot.eu-west-1.amazonaws.com/topics/90613aac-404e-47ea-8775-217db52a0b34%2Feu-west-1%3A0dee80a0-cc10-4e01-9f84-34ca36d06cbb%2Fproxy?qos=1",
      headers: headers,
      data: body,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.log.info("Topic subscribed");
        return res.data;
      })
      .catch((error) => {
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      });

    this.ws = new WebSocket("wss://remoteproxy.nymea.io", {
      perMessageDeflate: false,
    });
    this.reconnecing = false;
    this.ws.on("close", () => {
      this.log.info("Websocket closed");
      if (!this.reconnecing) {
        this.reconnecing = true;
        this.connectToWS();
      }
    });
    this.ws.on("open", () => {
      this.log.info("Websocket open");
      try {
        this.ws.send(JSON.stringify({ id: 0, method: "RemoteProxy.Hello" }));
        this.ws.send(
          JSON.stringify({
            id: 0,
            method: "Authentication.Authenticate",
            params: {
              name: "maveo-app",
              nonce: this.nonce,
              token: this.session.idToken,
              uuid: uuidv4(),
            },
          })
        );
      } catch (error) {
        this.log.error(error);
      }
    });

    this.ws.on("message", async (data, isBinary) => {
      const message = isBinary ? data : data.toString();
      // this.log.debug("WS received:" + message);
      this.reconnectTimeout && clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = setTimeout(() => {
        this.log.info("WS reconnecting");
        this.reconnecing = true;
        this.connectToWS();
      }, 11 * 60 * 1000);
      try {
        let parsed = {};
        let messageArray = [];
        try {
          if (message.startsWith('{"id":')) {
            messageArray = message.split("\n");
            this.currentMessage = message;
            message;
            parsed = JSON.parse(message);
            this.log.debug(`Parsed successfully: ${parsed.id}`);
          } else {
            this.currentMessage += message;
            parsed = JSON.parse(this.currentMessage);
            this.log.debug(`Parsed successfully: ${parsed.id}`);
          }
        } catch (error) {
          this.log.debug("Parsing failed wait for next message " + message.substring(0, 15));
          if (messageArray <= 2) {
            return;
          }
        }
        if (parsed.status === "error") {
          this.log.error(message);
          return;
        }
        if (parsed.notification === "RemoteProxy.TunnelEstablished") {
          this.ws.send(
            JSON.stringify({
              id: 1,
              method: "JSONRPC.Hello",
              params: {
                locale: "de_DE",
              },
              token: null,
            })
          );
          await this.sleep(1000);
          this.log.debug("WS sending:" + 2);
          this.ws.send(
            '{"id":2,"method":"JSONRPC.SetNotificationStatus","params":{"namespaces":["System","JSONRPC","Integrations","Rules","Logging","Configuration","Tags","Scripts"]},"token":null}'
          );

          await this.sleep(1000);
          this.log.debug("WS sending:" + 3);
          this.ws.send('{"id":3,"method":"JSONRPC.IsCloudConnected","token":null}');

          if (!this.thingClasses) {
            await this.sleep(1000);

            this.log.debug("WS sending:" + 5);
            this.ws.send('{"id":5,"method":"Integrations.GetThingClasses","token": null}');
            await this.sleep(5000);

            this.log.debug("WS sending:" + 6);
            this.ws.send('{"id":6,"method":"Integrations.GetThings","token":null}');
          }
        }
        if (parsed.id === 5) {
          this.thingClasses = {};
          this.stateTypes = {};
          const reply = parsed.params;
          for (let i = 0; i < reply.thingClasses.length; i++) {
            let thingClass = reply.thingClasses[i];
            // Convert stateTypes from a list to a map for easier lookup
            let stateTypes = {};
            for (let j = 0; j < thingClass.stateTypes.length; j++) {
              let stateType = thingClass.stateTypes[j];
              stateTypes[stateType.id] = stateType;
            }
            thingClass.stateTypes = stateTypes;
            this.stateTypes = { ...this.stateTypes, ...stateTypes };
            // Convert actionTyes from a list to a map or easier lookup
            let actionTypes = {};
            for (let j = 0; j < thingClass.actionTypes.length; j++) {
              let actionType = thingClass.actionTypes[j];
              actionTypes[actionType.id] = actionType;
            }
            thingClass.actionTypes = actionTypes;

            this.thingClasses[thingClass.id] = thingClass;
          }
        }
        if (parsed.id === 6) {
          this.things = {};
          const reply = parsed.params;
          for (let i = 0; i < reply.things.length; i++) {
            this.things[reply.things[i].id] = reply.things[i];
            let thing = reply.things[i];
            let thingClass = this.thingClasses[thing.thingClassId];
            // Convert states from a list to a map for easier lookup
            let states = {};
            for (let j = 0; j < thing.states.length; j++) {
              let state = thing.states[j];
              states[state.stateTypeId] = state;
            }
            thing["states"] = states;
          }
        }
        if (messageArray.length > 2 || (parsed.notification === "Integrations.StateChanged" && parsed.params)) {
          for (let parsed of messageArray) {
            if (!parsed) {
              continue;
            }
            parsed = JSON.parse(parsed);
            if (parsed.notification != "Integrations.StateChanged" || !parsed.params) {
              continue;
            }
            const thingId = parsed.params.thingId;
            const stateTypeId = parsed.params.stateTypeId;
            const stateType = this.stateTypes[stateTypeId];
            this.log.debug(JSON.stringify(stateType));
            let unit = stateType.unit === "UnitNone" ? null : stateType.unit.replace("Unit", "");

            await this.setObjectNotExistsAsync(parsed.params.thingId, {
              type: "device",
              common: {
                name: "",
              },
              native: {},
            });

            await this.setObjectNotExistsAsync(thingId + "." + stateTypeId, {
              type: "state",
              common: {
                name: stateType.displayName,
                type: "mixed",
                role: stateType.unit === "UnitUnixTime" ? "date" : "value",
                write: true,
                read: true,
                unit: unit,
              },
              native: {},
            });
            if (stateType.unit === "UnitUnixTime") {
              parsed.params.value = parsed.params.value * 1000;
            }
            this.setState(thingId + "." + stateTypeId, parsed.params.value, true);
          }
        }
      } catch (error) {
        this.log.error(error);
      }
    });

    this.ws.on("error", (err) => {
      this.log.error("websocket error: " + err);
    });
  }
  async refreshToken() {
    this.log.debug("Refreshing token");
    const token = new AmazonCognitoIdentity.CognitoRefreshToken({
      RefreshToken: this.session.refreshToken,
    });
    this.cognitoUser.refreshSession(token, async (err, result) => {
      if (err) {
        this.log.error(JSON.stringify(err));
        return;
      }
      this.log.debug(JSON.stringify(result));
      this.session.idToken = result.idToken.jwtToken;
      this.session.refreshToken = result.refreshToken.token;
      await this.requestClient({
        method: "post",
        url: "https://cognito-identity.eu-west-1.amazonaws.com/?Action=GetCredentialsForIdentity&Version=2016-06-30",
        headers: {
          "Content-Type": "application/x-amz-json-1.0",
          Host: "cognito-identity.eu-west-1.amazonaws.com",
          "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
          Connection: "Keep-Alive",
          "Accept-Language": "de-DE,en,*",
          "User-Agent": "Mozilla/5.0",
        },
        data:
          '{"IdentityId":"eu-west-1:0dee80a0-cc10-4e01-9f84-34ca36d06cbb","Logins":{"cognito-idp.eu-west-1.amazonaws.com/eu-west-1_d4DdcqKJ8":"' +
          this.session.idToken +
          '"}}',
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          this.session.Credentials = res.data.Credentials;

          return res.data;
        })
        .catch((error) => {
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
        });
    });
  }
  sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  amzDate() {
    return new Date().toISOString().slice(0, 20).replace(/-/g, "").replace(/:/g, "").replace(/\./g, "") + "Z";
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
      clearTimeout(this.refreshTimeout);
      clearTimeout(this.reLoginTimeout);
      clearTimeout(this.refreshTokenTimeout);
      clearInterval(this.updateInterval);
      clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const command = id.split(".")[4];
        const data = {};
        this.log.debug(JSON.stringify(data));
        await this.requestClient({
          method: "post",
          url: "",
          headers: {
            "accept-charset": "UTF-8, ISO-8859-1",
            "x-api-idtoken": this.session.idToken,
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-A805F Build/PPR1.180610.011)",
          },
          data: data,
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            return res.data;
          })
          .catch((error) => {
            this.log.error(error);
            if (error.response) {
              this.log.error(JSON.stringify(error.response.data));
            }
          });
      }
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Maveo(options);
} else {
  // otherwise start the instance directly
  new Maveo();
}
