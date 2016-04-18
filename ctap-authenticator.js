var cbor = require('cbor');
var cbor2 = require("cbor-js");

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

				var x = cbor2.decode (toArrayBuffer(res));
				console.log ("x:");
				console.log (x);
				// parse & validate
				parseStupidMap(res, function(err, paramList) {
					if (err) {
						reject (err);
					}

					if (paramList.length < 2 || paramList.length > 3) {
						reject (Error ("too many parameters in response"));
					}

					// TODO: validate params

					// convert params back to JSON objects
					var ret = {};
					var p = [];
					p.push(cbor.decodeFirst(paramList[0]));
					p.push(cbor.decodeFirst(paramList[1]));
					if (paramList.length === 3) p.push(cbor.decodeFirst(paramList[2]));
					Promise.all(p)
						.then(function(resList) {
							ret.credential = resList[0];
							ret.credentialPublicKey = resList[1].toString("hex");
							if (paramList.length === 3) ret.rawAttestation = resList[2];
							resolve(ret);
						})
						.catch(function(err) {
							reject(err);
						});
				});
			});
		});

	}.bind(this));
};

// XXX: this isn't very flexible, but the only reason I have to write this is becuase someone didn't follow the advice of RFC 7049
// "3.7.  Specifying Keys for Maps
// In applications that need to interwork with JSON-based applications, keys probably should be
// limited to UTF-8 strings only; "
function parseStupidMap (cbor, cb) {
	var numParams, i, j;
	var type, len, pos = 0;
	var ret = [];

	if (Array.isArray(cbor)) {
		cbor = new Buffer(cbor);
	}
	numParams = cbor[0] & CBOR_TYPE.LENGTH_MASK;
	if (numParams >= CBOR_TYPE.LENGTH_ONE) {
		return cb (Error ("too many items in map: map sizes over 17 currently not supported"));
	}
	pos++; // assuming the map has less than 18 items...


	require("hex")(cbor);
	for (i = 1; i <= numParams; i++) {

		// check that map key = parameter number
		if (cbor[pos] !== i) {
			return cb (Error ("Parsing param " + i + " but map key didn't match"));
		}
		pos++;

		// figure out how long this element is
		len = decodeCborLength(cbor, pos);
		if (len === null) {
			cb (Error ("Couldn't decode length of CBOR element"));
		}

		// create buffer
		var b = new Buffer(len);
		var c = cbor.copy(b, 0, pos, pos + len);
		if (c != len) {
			cb (Error ("error copying cbor to new buffer"));
		}
		console.log ("Buf " + i);
		require("hex")(b);
		pos += len;
		console.log ("new pos:", pos);

		// push buffer on to return array
		ret.push(b);
	}

	cb (null, ret);
}

// get the real length of a CBOR element, including header bytes
function decodeCborLength (buf, pos)
{
	console.log ("Decoding buf @ pos:", pos);
	require ("hex")(buf);
	var cbor = [
		buf[pos],
		buf[pos + 1],
		buf[pos + 2],
		buf[pos + 3]
	];
	var headerSz = 1;

	// if type is integer, it's just a one byte header and no data
	if ((cbor[0] & CBOR_TYPE.MAJOR_MASK) === 0) {
		console.log ("Decoding at " + pos + " was int");
		return headerSz;
	}

	var len = cbor[0] & CBOR_TYPE.LENGTH_MASK;
	if (len < CBOR_TYPE.LENGTH_ONE) {
		console.log ("Decoding at " + pos + " was small");	
		return len + headerSz;
	}
	switch (len) {
		case CBOR_TYPE.LENGTH_ONE:
			headerSz = 2;
			len = cbor [1] + headerSz;
			break;
		case CBOR_TYPE.LENGTH_TWO:
			headerSz = 3;
			len = (cbor[1] << 8) + cbor[2] + headerSz;
			break;
		case CBOR_TYPE.LENGTH_THREE:
			headerSz = 4;
			len = (cbor[1] << 16) + (cbor[2] << 8) + cbor[3] + headerSz;
			break;
		case CBOR_TYPE.LENGTH_INDEFINITE: // not supported yet
			console.log ("WARNING: got indefinite length, not currently supported");
			return null;
		default:
			return null;
	}

	// maps report number of elements, not real length
	var i, mapCnt;
	if ((cbor[0] & CBOR_TYPE.MAJOR_MASK) === CBOR_TYPE.MAP) {
		console.log ("getting length for map");
		mapCnt = len;
		len = 0;
		for (i = 0; i < mapCnt*2; i++) {
			len += decodeCborLength (buf, pos + len);
		}
	}

	console.log ("Done decoding @ ", pos);
	return len;
}

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


// TODO?
// Auth.prototype.AuthError = function (message) {
// 	this.name = "AuthError";
// 	this.message = (message || "");
// };
// Auth.prototype.AuthError.prototype = Error.prototype;