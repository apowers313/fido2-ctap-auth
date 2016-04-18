var cbor = require("cbor-js");

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
	FLOAT: 0xe0,
	// for bitwise operations
	MAJOR_MASK: 0xE0,
	LENGTH_MASK: 0x1F,
	LENGTH_ONE: 0x18,
	LENGTH_TWO: 0x19,
	LENGTH_THREE: 0x1A,
	LENGTH_INDEFINITE: 0x1F
};

// setup prototype
module.exports = Auth;

function Auth(send, receive, options) {
	if (typeof auth === "string") {
		console.log("FFI not supported yet");
	}

	this.externalSend = send;
	this.externalReceive = receive;
}

Auth.prototype.authenticatorMakeCredential = function(rpId, clientDataHash, account, cryptoParameters, blacklist, extensions) {
	return new Promise(function(resolve, reject) {
		var argCnt = 0;
		var params = [];

		// create parameters
		// TODO: each parameter needs a bit more verification; e.g. - manatory attributes of objects
		if (rpId !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.RPID] = new Uint8Array(cbor.encode(rpId));
		} else {
			reject(Error("rpId parameter required"));
		}

		if (clientDataHash !== undefined) {
			argCnt++;
			var buf = hexStr2TypedArray(clientDataHash);
			if (buf === null) {
				reject(Error("couldn't convert clientDataHash to TypedArray"));
			}
			params[MAKE_CREDENTIAL_PARAMETERS.CLIENT_DATA_HASH] = new Uint8Array(cbor.encode(buf));
		} else {
			reject(Error("clientDataHash parameter required"));
		}

		if (account !== undefined) {
			// TODO: check account info
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.ACCOUNT] = new Uint8Array(cbor.encode(account));
		} else {
			reject(Error("account parameter required"));
		}

		if (cryptoParameters !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.CRYPTO_PARAMTERS] = new Uint8Array(cbor.encode(cryptoParameters));
		} else {
			reject(Error("cryptoParameters parameter required"));
		}

		if (blacklist !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.BLACKLIST] = new Uint8Array(cbor.encode(blacklist));
		}

		if (extensions !== undefined) {
			argCnt++;
			params[MAKE_CREDENTIAL_PARAMETERS.EXTENSIONS] = new Uint8Array(cbor.encode(extensions));
		}

		// XXX: this isn't very flexible, but the only reason I have to write this is becuase someone didn't follow the advice of RFC 7049
		// "3.7.  Specifying Keys for Maps
		// In applications that need to interwork with JSON-based applications, keys probably should be limited to UTF-8 strings only; "

		// create message
		var cborMsg = new Uint8Array([CTAP_COMMAND.MAKE_CREDENTIAL, (CBOR_TYPE.MAP + argCnt)]);
		var i, param, len = 2, newCborMsg;
		for (i = 0; i < MAKE_CREDENTIAL_PARAMETERS.MAX_PARAMETERS; i++) {
			if (params[i] !== undefined) {
				// this creates appends the key:value of the map onto the back of the cborMsg
				// where "key" is i (the parameter number) and "value" is params[i];
				// XXX: there's a lot of data copying here, which really sucks performance-wise
				newCborMsg = new Uint8Array (cborMsg.length + 1 + params[i].length);
				newCborMsg.set (cborMsg);
				newCborMsg.set ([i], cborMsg.length);
				newCborMsg.set (params[i], cborMsg.length + 1);

				cborMsg = newCborMsg;
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

				var response;
				try {
					response = cbor.decode (toArrayBuffer(res));
				} catch (err) {
					err.message = "Error parsing CBOR response message:" + err.message;
					reject(Error(err));
				}

				// validation of number of parameters
				if (response["1"] === undefined || 
					response["2"] === undefined) {
					reject(Error("Expected at least two parameters in response message"));
				}

				// validation of first parameter
				if (typeof response["1"] !== "object" ||
					response["1"].type === undefined || // redundant
					response["1"].type !== "FIDO" ||
					response["1"].id === undefined ||
					typeof response["1"].id !== "string") {
					reject(Error("First in response parameter had wrong format:" + response["1"]));
				}

				// validation of second parameter
				if (!(response["2"] instanceof Uint8Array)) {
					reject(Error("Expected second parameter in response message to be Uint8Array"));
				}

				// TODO: validation of third parameter

				// massage the data a little bit to match our expected return values
				var ret = {};
				ret.credential = response["1"];
				// ret.credentialPublicKey = response["2"].buffer;
				ret.credentialPublicKey = typedArray2HexStr(response["2"]);
				if (response["3"] !== undefined) ret.rawAttestation = response["3"];
				// console.log (ret);
				resolve (ret);
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

function toArrayBuffer(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return ab;
}

var hex2intLookup;
function hexStr2TypedArray(str) {
	var hex, i;
	str = str.toLowerCase();

	// if this is our first time, create our hex lookup table
	if (hex2intLookup === undefined) {
		hex2intLookup = [];
		for (i = 0; i < 256; i++) {
			// create lowercase lookup
			hex = i.toString(16).toLowerCase();
			if (hex.length == 1) hex = "0" + hex;
			hex2intLookup[hex] = i;
		}
	}

	// if we don't have an even number of bytes, it's not a valid hex string
	if ((str.length%2) !== 0) {
		return null;
	}

	// convert each byte...
	var arr = new Uint8Array(str.length / 2);
	for (i = 0; i < str.length/2; i++) {
		hex = str[i*2] + str[(i*2)+1];
		arr[i] = hex2intLookup[hex];
		if (arr[i] === undefined) return null;
	}
	return arr;
}

function typedArray2HexStr(ta) {
	var i, hex, str="";
	for (i = 0; i < ta.length; i++) {
		hex = ta[i].toString(16);
		if (hex.length === 1) hex = "0" + hex;
		str = str + hex;
	}
	return str;
}

// TODO?
// Auth.prototype.AuthError = function (message) {
// 	this.name = "AuthError";
// 	this.message = (message || "");
// };
// Auth.prototype.AuthError.prototype = Error.prototype;