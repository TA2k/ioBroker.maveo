"use strict";

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
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
        this.requestClient = axios.create();
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.json2iob = new Json2iob(this);
        this.deviceArray = [];

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
                UserPoolId: "eu-west-1_d4DdcqKJ8",
                ClientId: "6jht51ls3kqt7rrl4ff414u1jr",
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
                            "Host": "cognito-identity.eu-west-1.amazonaws.com",
                            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
                            "Connection": "Keep-Alive",
                            "Accept-Language": "de-DE,en,*",
                            "User-Agent": "Mozilla/5.0"
                        },
                        data : '{"IdentityId":"eu-west-1:daee25fd-ba28-45c2-976e-1590bbf101c4","Logins":{"cognito-idp.eu-west-1.amazonaws.com/eu-west-1_d4DdcqKJ8":"' + this.session.idToken + '"}}',
                    })
                        .then((res) => {
                            this.log.debug(JSON.stringify(res.data));
                            this.session.Credentials =res.data.Credentials;

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
        this.nonce = "{"+uuidv4()+"}";
        const body =JSON.stringify({
            "nonce":this.nonce,
            "timestamp": this.nonce,
            "token": this.session.idToken,
        })
        const headers={
            "content-type": "application/json",
            "X-Amz-Date": this.amzDate(),
            "x-amz-security-token": this.session.Credentials.SessionToken,
            "User-Agent": "Mozilla/5.0"
        };
        const signed = aws4.sign(
            {
                host: "a27q7a2x15m8h3-ats.iot.eu-west-1.amazonaws.com",
                path: "/topics/90613aac-404e-47ea-8775-217db52a0b34%2Feu-west-1%3Adaee25fd-ba28-45c2-976e-1590bbf101c4%2Fproxy?qos=1",
                service: "iotdata",
                method: "POST",
                region: "eu-west-1",
                headers: headers,
                body:body
            },
            { accessKeyId: this.session.Credentials.AccessKeyId, secretAccessKey: this.session.Credentials.SecretKey }
        );
        headers["Authorization"] =signed.headers["Authorization"],
        await this.requestClient({
            method: "post",
            url: "https://a27q7a2x15m8h3-ats.iot.eu-west-1.amazonaws.com/topics/90613aac-404e-47ea-8775-217db52a0b34%2Feu-west-1%3Adaee25fd-ba28-45c2-976e-1590bbf101c4%2Fproxy?qos=1",
            headers: headers,
            data:  body,
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
            });

        if (this.ws) {
            this.ws.close();
        }
        this.ws = new WebSocket("wss://remoteproxy.nymea.io", {
            perMessageDeflate: false,
        });

        this.ws.on("open", () => {
            this.log.info("Websocket open");
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
        });

        this.ws.on("message",async (message) => {
            this.log.info("WS received:" + message);
            try {
                const parsed = JSON.parse(message);
                if (parsed.notification ==="RemoteProxy.TunnelEstablished") {
                    this.log.info("WS TunnelEstablished");
                    this.ws.send(
                        JSON.stringify({
                            "id": 1,
                            "method": "JSONRPC.Hello",
                            "params": {
                                "locale": "de_DE"
                            },
                            "token": null
                        })
                    );
                    this.ws.send(
                        JSON.stringify({
                            "id": 2,
                            "method": "JSONRPC.SetNotificationStatus",
                            "params": {
                                "namespaces": [
                                    "Tags",
                                    "Integrations",
                                    "JSONRPC",
                                    "System",
                                    "Scripts",
                                    "Configuration",
                                    "Rules"
                                ]
                            },
                            "token": null
                        })
                    );
                    // this.ws.send(
                    //     JSON.stringify({
                    //         "id": 5,
                    //         "method": "Integrations.GetThingClasses",
                    //         "token": null
                    //     })
                    // );
                }
                if (parsed.notification==="Integrations.StateChanged" && parsed.params) {
                    await this.setObjectNotExistsAsync(parsed.params.thingId, {
                        type: "device",
                        common: {
                            name: "",
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(parsed.params.thingId+"."+parsed.params.stateTypeId, {
                        type: "state",
                        common: {
                            name: "",
                            type: "mixed",
                            role: "value",
                            write: true,
                            read: true,
                        },
                        native: {},
                    });
                    this.setState(parsed.params.thingId+"."+parsed.params.stateTypeId,parsed.params.value,true);
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
        const token = new AmazonCognitoIdentity.CognitoRefreshToken({
            RefreshToken: this.session.refreshToken,
        });
        this.cognitoUser.refreshSession(token, (err, result) => {
            if (err) {
                this.log.error(JSON.stringify(err));
                return;
            }
            this.session.idToken = result.idToken.jwtToken;
            this.session.refreshToken = result.refreshToken.token;
        });
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
