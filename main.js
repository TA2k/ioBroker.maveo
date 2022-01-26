"use strict";

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
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
        this.session = {};

        await this.login();

        if (this.session.idToken) {
            await this.getDeviceList();
            await this.updateDevices();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, this.config.interval * 60 * 1000);
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
                onSuccess: (result) => {
                    this.session.idToken = result.idToken.jwtToken;
                    this.session.refreshToken = result.refreshToken.token;

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
                            name: id,
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

    async updateDevices() {
        const statusArray = [
            {
                path: "status",
                url: "https://api-cloud.nymea.io/users/devices/$id",
                desc: "Status of the device",
            },
        ];

        const headers = {
            "accept-charset": "UTF-8, ISO-8859-1",
            "x-api-idtoken": this.session.idToken,
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-A805F Build/PPR1.180610.011)",
        };
        this.deviceArray.forEach(async (id) => {
            statusArray.forEach(async (element) => {
                const url = element.url.replace("$id", id);

                await this.requestClient({
                    method: "get",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data) {
                            return;
                        }
                        const data = res.data;

                        const forceIndex = null;
                        const preferedArrayName = null;

                        this.json2iob.parse(id + "." + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    })
                    .catch((error) => {
                        if (error.response && error.response.status === 401) {
                            error.response && this.log.debug(JSON.stringify(error.response.data));
                            this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
                            clearTimeout(this.refreshTokenTimeout);
                            this.refreshTokenTimeout = setTimeout(() => {
                                this.refreshToken();
                            }, 1000 * 60);

                            return;
                        }

                        this.log.error(url);
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            });
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
                clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(async () => {
                    await this.updateDevices();
                }, 10 * 1000);
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
