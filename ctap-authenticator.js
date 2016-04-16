var program = require('commander');
var cbor = require('cbor');
var convHex = require("convert-hex");

var CTAP_COMMAND = {
	MAKE_CREDENTIAL: 0x01,
	GET_ASSERTION: 0x02,
	CANCEL: 0x03,
	GET_INFO: 0x04
};

var MAKE_CREDENTIAL_PARAMETERS = {
	RPID: 0x01,
	CLIENT_DATA_HASH: 0x02,
	ACCOUNT: 0x03,
	CRYPTO_PARAMTERS: 0x4,
	BLACKLIST: 0x05,
	EXTENSIONS: 0x06,
	MAX_PARAMETERS: 0x07
};

var MAKE_CREDENTIAL_RESPONSE = {
	CREDENTIAL: 0x01,
	CREDENTIAL_PUBLIC_KEY: 0x02,
	RAW_ATTESTATION: 0x03
};

var GET_ASSERTION_PARAMETERS = {
	RIPD: 0x01,
	CLIENT_DATA_HASH: 0x02,
	WHITELIST: 0x03,
	EXTENSIONS: 0x04,
	MAX_PARAMETERS: 0x05
};

var GET_ASSERTION_RESPONSE = {
	CREDENTIAL: 0x01,
	AUTHENTICATION_DATA: 0x02,
	SIGNATURE: 0x03
};

var GET_INFO_RESPONSE = {
	VERSIONS: 0x01,
	EXTENSIONS: 0x02,
	AAGUID: 0x03
};

var CBOR_TYPE = {
	UNSIGNED_INT: 0x00,
	NEGATIVE_INT: 0x20,
	BYTE_STRING: 0x40,
	TEXT_STRING: 0x60,
	ARRAY: 0x80,
	MAP: 0xa0,
	SEMANTIC_TAG: 0xc0,
	FLOAT: 0xe0
};

// setup prototype
module.exports = Auth;

function Auth(auth, options) {
	if (typeof auth === "string") {
		console.log("FFI not supported yet");
	}

	this.externalSend = auth.send;
	this.externalReceive = auth.receive;
}

Auth.prototype.authenticatorMakeCredential = function(rpId, clientDataHash, account, cryptoParameters, blacklist, extensions) {
	return new Promise(function(resolve, reject) {
		var argCnt = 0;
		var params = [];

		// create parameters
		// TODO: each parameter needs a bit more verification; e.g. - manatory attributes of objects
		if (rpId !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.RPID] = cbor.encode(rpId);
		} else {
			reject(Error("rpId parameter required"));
		}

		if (clientDataHash !== undefined) {
			argCnt++;
			var buf = new Buffer(clientDataHash, "hex");

			params[MAKE_CREDENTIAL_PARAMETERS.CLIENT_DATA_HASH] = cbor.encode(buf);
		} else {
			reject(Error("clientDataHash parameter required"));
		}

		if (account !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.ACCOUNT] = cbor.encode(account);
		} else {
			reject(Error("account parameter required"));
		}

		if (cryptoParameters !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.CRYPTO_PARAMTERS] = cbor.encode(cryptoParameters);
		} else {
			reject(Error("cryptoParameters parameter required"));
		}

		if (blacklist !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.BLACKLIST] = cbor.encode(blacklist);
		}

		if (extensions !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.EXTENSIONS] = cbor.encode(extensions);
		}

		// create message
		var cborMsg = new Buffer([CTAP_COMMAND.MAKE_CREDENTIAL, (CBOR_TYPE.MAP + argCnt)]);
		var i, param;
		for (i = 0; i < MAKE_CREDENTIAL_PARAMETERS.MAX_PARAMETERS; i++) {
			if (params[i] !== undefined) {
				param = Buffer.concat([new Buffer([i]), params[i]]);
				cborMsg = Buffer.concat([cborMsg, param]);
			}
		}

		// sendMessage
		var self = this; // could bind, but don't want the external function messing up our context
		this.externalSend(cborMsg, function(err, sendRes) {
			if (err) {
				reject(Error("Error sending message: " + err));
			}

			// receiveMessage
			self.externalReceive(function(err, res) {
				if (err) {
					reject(Error("Error receiving message: " + err));
				}

				// validate
				// return
				//    credential, publicKey, rawAttestation
				resolve (sendRes);
			});
		});

	}.bind(this));
};


Auth.prototype.authenticatorGetAssertion = function(rpId, clientDataHash, whitelist, extensions) {
	return new Promise(function(resolve, reject) {
		// authenticatorGetAssertion
		// create message
		// CBORize
		// sendMessage
		// receiveMessage
		// validate
		// return
		//     credential, authenticatorData, signature
	});
};

Auth.prototype.authenticatorCancel = function() {
	// this.pending
	return new Promise(function(resolve, reject) {});
};

Auth.prototype.authenticatorGetInfo = function() {
	return new Promise(function(resolve, reject) {
		// return
		//    versions, extensions, aaguid
	});
};

Auth.prototype.sendMessage = function(json, cb) {
	return new Promise(function(resolve, reject) {
		var msg;

		// validate message
		try {
			msg = JSON.parse(json);
		} catch (err) {
			reject(Error("Message must be valid JSON"));
		}

		// CBORize
		var cborMsg = cbor.encode(msg);

		// sendMessage
		this.externalSend(cborMsg, function(err, res) {
			if (err) {
				console.log("Error sending message:", err);
				reject(Error("Error sending message: " + err));
			}
			resolve(res);
		});
	}.bind(this));
};

Auth.prototype.receiveMessage = function(cb) {
	return new Promise(function(resolve, reject) {
		this.externalReceive(function(err, msg) {
			if (err) {
				console.log("Error receiving message:", err);
				reject(Error("Error receiving message: " + err));
			}
			resolve(msg);
		});
	}.bind(this));
};


// TODO?
// Auth.prototype.AuthError = function (message) {
// 	this.name = "AuthError";
// 	this.message = (message || "");
// };
// Auth.prototype.AuthError.prototype = Error.prototype;