var hex = require("hex");
var cbor = require("cbor");
var cp = require("cbor-pretty-print");

var lastMsgType, nextResponseErr = false;

function helperSend(cborMsg, cb) {
	lastMsgType = cborMsg[0];
	cb(null, cborMsg);
}

function helperReceive(cb) {
	// var b = cbor.encode({
	// 	"1": {
	// 		"type": "FIDO",
	// 		"id": "a8f3c9ce-6f16-4130-ad5d-b1d521888b39"
	// 	},
	// 	"2": "0100000012",
	// 	"3": "\x30\x46\x02\x21\x00\xc5\x9e\x34\x84\xb0\x3f\x0c\xc9\x56\xea\x59\x69\xd8\x1b\xa9\x83\x06\xbc\xde\x89\xfe\x33\x1d\xce\x7e\xf6\x9e\x31\xca\x54\x35\xa3\x02\x21\x00\xe4\x88\x15\xed\x05\xa7\x61\x7a\x89\x79\x9a\xb9\x0f\xdc\x01\xa8\xdf\x97\x66\xb1\x5f\x45\xd5\x6b\x35\x0b\x95\xec\x0c\x61\x0d\x6d"
	// });
	// cp (b, {hexSyntax: true});
	if (nextResponseErr) {
		lastMsgType = 255;
	}
	switch (lastMsgType) {
		case 1:
			console.log("responding with makeCredResp");
			cb(null, helpers.makeCredRespCbor);
			return;
		case 2:
			console.log("responding with getAssertResp");
			cb(null, helpers.getAssertRespCbor);
			return;
		case 3:
			console.log("responding with cancelResp");
			cb(null, helpers.cancelResp);
			return;
		case 4:
			console.log("responding with getInfoResp");
			cb(null, helpers.getInfoResp);
			return;
		case 255: // fake condition for testing
			console.log("responding with Fake Error");
			cb(cbor.encode({
				error: "Fake Error"
			}));
			return;
		default: // fake condition for testing
			console.log("responding with defaultResp");
			cb(null, helpers.defaultResp);
			return;
	}
}
function typedArrayEquals (buf1, buf2)
{
    if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
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

var helpers = {
	clearLastMsg: function() { lastMsgType = undefined; },
	nextResponseErr: function() { nextResponseErr = true; },
	clearNextResponseErr: function() { nextResponseErr = false; },
	typedArrayEquals: typedArrayEquals,
	typedArray2HexStr: typedArray2HexStr,
	makeCredResp: {
		credential: {
			type: 'FIDO',
			id: 'a8f3c9ce-6f16-4130-ad5d-b1d521888b39'
		},
		credentialPublicKey: '3059301306072a8648ce3d020106082a8648ce3d030107034200040a45a34c8a30fb175eeb0af8122e444725dd69f34aee3fe47bb48bb5b15e532dc6e38381bf01a7f1200a6b8ebcacf364c294a7a796d8abb3523f38de90f2b97d'
	},
	getAssertResp: {
		credential: {
			type: "FIDO",
			id: "a8f3c9ce-6f16-4130-ad5d-b1d521888b39"
		},
		authenticatorData: "0100000012",
		signature: "3046022100c59e3484b03f0cc956ea5969d81ba98306bcde89fe331dce7ef69e31ca5435a3022100e48815ed05a7617a89799ab90fdc01a8df9766b15f45d56b350b95ec0c610d6d"
	},
	cancelResp: {}, // TODO
	getInfoResp: {}, // TODO
	defaultResp: {},  // TODO
	credential: {
		type: "FIDO",
		id: "a8f3c9ce-6f16-4130-ad5d-b1d521888b39"
	},
	makeCredArgs: {
		rpId: "paypal.com",
		clientDataHash: "5a81483d96b0bc15ad19af7f5a662e14b275729fbc05579b18513e7f550016b1",
		account: {
			rpDisplayName: "PayPal",
			displayName: "John P. Smith",
			name: "johnpsmith@gmail.com",
			id: "1098237235409872",
			imageUri: "https://pics.paypal.com/00/p/aBjjjpqPb.png"
		},
		cryptoParameters: [{
			type: "FIDO",
			algorithm: "ES256"
		}, {
			type: "FIDO",
			algorithm: "RS256"
		}]
	},
	helperAuth: {
		send: helperSend,
		receive: helperReceive
	},
	send: helperSend,
	receive: helperReceive,
	authenticatorMakeCredentialCommandCbor: [
		0x01                                         , // authenticatorMakeCredential command
        0xa4                                         , // map(4)
           0x01                                      , // unsigned(1) -- rpId
           0x6a                                      , // text(10)
              0x70, 0x61, 0x79, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d,                 
              										   // "paypal.com"
           0x02                                      , // unsigned(2) -- clientDataHash
           0x58, 0x20                                , // byte string(32)
              0x5a, 0x81, 0x48, 0x3d, 0x96, 0xb0, 0xbc, 0x15, 0xad, 0x19, 0xaf, 0x7f, 0x5a, 0x66, 0x2e, 0x14, 0xb2, 0x75, 0x72, 0x9f, 0xbc, 0x05, 0x57, 0x9b, 0x18, 0x51, 0x3e, 0x7f, 0x55, 0x00, 0x16, 0xb1, 
              									       // sha256 hash
           0x03                                      , // unsigned(3) -- account
           0xa5                                      , // map(5)
              0x6d                                   , // text(13)
                 0x72, 0x70, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 
                 									   // "rpDisplayName"
              0x66                                   , // text(6)
                 0x50, 0x61, 0x79, 0x50, 0x61, 0x6c  , // "PayPal"
              0x6b                                   , // text(11)
                 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 
                 									   // "displayName"
              0x6d                                   , // text(13)
                 0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x50, 0x2e, 0x20, 0x53, 0x6d, 0x69, 0x74, 0x68, 
                 									   // "John P. Smith"
              0x64                                   , // text(4)
                 0x6e, 0x61, 0x6d, 0x65              , // "name"
              0x74                                   , // text(20)
                 0x6a, 0x6f, 0x68, 0x6e, 0x70, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 
                 									   // "johnpsmith@gmail.com"
              0x62                                   , // text(2)
                 0x69, 0x64                          , // "id"
              0x70                                   , // text(16)
                 0x31, 0x30, 0x39, 0x38, 0x32, 0x33, 0x37, 0x32, 0x33, 0x35, 0x34, 0x30, 0x39, 0x38, 0x37, 0x32, 
                 									   // "1098237235409872"
              0x68                                   , // text(8)
                 0x69, 0x6d, 0x61, 0x67, 0x65, 0x55, 0x72, 0x69, 
                 									  // "imageUri"
              0x78, 0x2a                            , // text(42)
                 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x70, 0x69, 0x63, 0x73, 0x2e, 0x70, 0x61, 0x79, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x30, 0x2f, 0x70, 0x2f, 0x61, 0x42, 0x6a, 0x6a, 0x6a, 0x70, 0x71, 0x50, 0x62, 0x2e, 0x70, 0x6e, 0x67, 
                 									  // "https://pics.paypal.com/00/p/aBjjjpqPb.png"
           0x04                                      , // unsigned(4) -- cryptoParameters
           0x82                                      , // array(2)
              0xa2                                   , // map(2)
                 0x64                                , // text(4)
                    0x74, 0x79, 0x70, 0x65           , // "type"
                 0x64                                , // text(4)
                    0x46, 0x49, 0x44, 0x4f           , // "FIDO"
                 0x69                                , // text(9)
                    0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 
                    							       // "algorithm"
                 0x65                                , // text(5)
                    0x45, 0x53, 0x32, 0x35, 0x36     , // "ES256"
              0xa2                                   , // map(2)
                0x64                                 , // text(4)
                    0x74, 0x79, 0x70, 0x65           , // "type"
                 0x64                                , // text(4)
                    0x46, 0x49, 0x44, 0x4f           , // "FIDO"
                 0x69                                , // text(9)
                    0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 
                    								   // "algorithm"
                 0x65                                , // text(5)
                    0x52, 0x53, 0x32, 0x35, 0x36       // "RS256"
],

derEccPublicKey: [
0x30, 0x59, 												// sequence(2)
	0x30, 0x13, 											// sequence(2)
		0x06, 0x07, 										// OID
			0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 		// 1.2.840.10045.2.1 = EC Public Key
		0x06, 0x08, 										// OID
			0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7 = secp256r1
	0x03, 0x42, 											// bit string(520 bit) = Public Key
		0x00, 0x04, 0x0A, 0x45, 0xA3, 0x4C, 0x8A, 0x30, 	// ...
		0xFB, 0x17, 0x5E, 0xEB, 0x0A, 0xF8, 0x12, 0x2E, 	// ...
		0x44, 0x47, 0x25, 0xDD, 0x69, 0xF3, 0x4A, 0xEE, 	// ...
		0x3F, 0xE4, 0x7B, 0xB4, 0x8B, 0xB5, 0xB1, 0x5E, 	// ...
		0x53, 0x2D, 0xC6, 0xE3, 0x83, 0x81, 0xBF, 0x01, 	// ...
		0xA7, 0xF1, 0x20, 0x0A, 0x6B, 0x8E, 0xBC, 0xAC, 	// ...
		0xF3, 0x64, 0xC2, 0x94, 0xA7, 0xA7, 0x96, 0xD8, 	// ...
		0xAB, 0xB3, 0x52, 0x3F, 0x38, 0xDE, 0x90, 0xF2, 	// ...
		0xB9, 0x7D											// ...
],

credentialCbor: [
0xA2, 														// map(2)
	0x64, 													// text(4)
		0x74, 0x79, 0x70, 0x65, 							// "type"
	0x64, 													// text(4)
		0x46, 0x49, 0x44, 0x4F, 							// "FIDO"
	0x62, 													// text(2)
		0x69, 0x64, 										// "id"
	0x78, 0x24, 											// text(36)
		0x61, 0x38, 0x66, 0x33, 0x63, 0x39, 0x63, 0x65, 	// "a8f3c9ce-6f16-4130-ad5d-b1d521888b39"
		0x2D, 0x36, 0x66, 0x31, 0x36, 0x2D, 0x34, 0x31, 	// ...
		0x33, 0x30, 0x2D, 0x61, 0x64, 0x35, 0x64, 0x2D, 	// ...
		0x62, 0x31, 0x64, 0x35, 0x32, 0x31, 0x38, 0x38, 	// ...
		0x38, 0x62, 0x33, 0x39								// ...
],

makeCredRespCbor: [
	0xa2, 																			// map(2)
		0x01, 																		// integer 1 = param 1
		0xA2, 																		// map(2)
			0x64, 																	// text(4)
				0x74, 0x79, 0x70, 0x65, 											// "type"
			0x64, 																	// text(4)
				0x46, 0x49, 0x44, 0x4F, 											// "FIDO"
			0x62, 																	// text(2)
				0x69, 0x64, 														// "id"
			0x78, 0x24, 															// text(36)
				0x61, 0x38, 0x66, 0x33, 0x63, 0x39, 0x63, 0x65, 					// "a8f3c9ce-6f16-4130-ad5d-b1d521888b39"
				0x2D, 0x36, 0x66, 0x31, 0x36, 0x2D, 0x34, 0x31, 					// ...
				0x33, 0x30, 0x2D, 0x61, 0x64, 0x35, 0x64, 0x2D, 					// ...
				0x62, 0x31, 0x64, 0x35, 0x32, 0x31, 0x38, 0x38, 					// ...
				0x38, 0x62, 0x33, 0x39,												// ...
		0x02, 																		// integer 2 = param 2
		0x58, 0x5B, 																// byte(91)
			// begin DER encoded public key 										// DER public key
			0x30, 0x59, 															// DER sequence(2)
				0x30, 0x13, 														// DER sequence(2)
					0x06, 0x07, 													// DER OID
						0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 					// DER 1.2.840.10045.2.1 = EC Public Key
					0x06, 0x08, 													// DER OID
						0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 			// DER 1.2.840.10045.3.1.7 = secp256r1
				0x03, 0x42, 														// DER bit string(520 bit) = Public Key
					0x00, 0x04, 0x0A, 0x45, 0xA3, 0x4C, 0x8A, 0x30, 				// ...
					0xFB, 0x17, 0x5E, 0xEB, 0x0A, 0xF8, 0x12, 0x2E, 				// ...
					0x44, 0x47, 0x25, 0xDD, 0x69, 0xF3, 0x4A, 0xEE, 				// ...
					0x3F, 0xE4, 0x7B, 0xB4, 0x8B, 0xB5, 0xB1, 0x5E, 				// ...
					0x53, 0x2D, 0xC6, 0xE3, 0x83, 0x81, 0xBF, 0x01, 				// ...
					0xA7, 0xF1, 0x20, 0x0A, 0x6B, 0x8E, 0xBC, 0xAC, 				// ...
					0xF3, 0x64, 0xC2, 0x94, 0xA7, 0xA7, 0x96, 0xD8, 				// ...
					0xAB, 0xB3, 0x52, 0x3F, 0x38, 0xDE, 0x90, 0xF2, 				// ...
					0xB9, 0x7D														// ...
],

getAssertRespCbor: [
0xa3,                                                       // map(3)
  0x01,                                                     // integer 1
  0xa2,                                                     // map(2)
    0x64,                                                   // text(4)
      0x74, 0x79, 0x70, 0x65,                               // "type"
    0x64,                                                   // text(4)
      0x46, 0x49, 0x44, 0x4f,                               // "FIDO"
    0x62,                                                   // text(2)
      0x69, 0x64,                                           // "id"
    0x78, 0x24,                                             // text(36)
      0x61, 0x38, 0x66, 0x33, 0x63, 0x39, 0x63, 0x65,       // "a8f3c9ce-6f16-4130-ad5d-b1d521888b39"
      0x2d, 0x36, 0x66, 0x31, 0x36, 0x2d, 0x34, 0x31,       // ...
      0x33, 0x30, 0x2d, 0x61, 0x64, 0x35, 0x64, 0x2d,       // ...
      0x62, 0x31, 0x64, 0x35, 0x32, 0x31, 0x38, 0x38,       // ...
      0x38, 0x62, 0x33, 0x39,                               // ...
  0x02,                                                     // integer 2
  0x45,                                                     // byte(5)
  	0x01, 0x00, 0x00, 0x00, 0x12,                           // "0100000012"
  0x03,                                                     // integer 3
  0x58, 0x48,                                               // byte(144)
    0x30, 0x46, 0x02, 0x21, 0x00, 0xc5, 0x9e, 0x34,         // "3046022100c59e3484b03f0cc956ea5969d81ba98306bcde89fe331dce7ef69e31ca5435a3022100e48815ed05a7617a89799ab90fdc01a8df9766b15f45d56b350b95ec0c610d6d"
    0x84, 0xb0, 0x3f, 0x0c, 0xc9, 0x56, 0xea, 0x59,         // ...
    0x69, 0xd8, 0x1b, 0xa9, 0x83, 0x06, 0xbc, 0xde,         // ...
    0x89, 0xfe, 0x33, 0x1d, 0xce, 0x7e, 0xf6, 0x9e,         // ...
    0x31, 0xca, 0x54, 0x35, 0xa3, 0x02, 0x21, 0x00,         // ...
    0xe4, 0x88, 0x15, 0xed, 0x05, 0xa7, 0x61, 0x7a,         // ...
    0x89, 0x79, 0x9a, 0xb9, 0x0f, 0xdc, 0x01, 0xa8,         // ...
    0xdf, 0x97, 0x66, 0xb1, 0x5f, 0x45, 0xd5, 0x6b,         // ...
    0x35, 0x0b, 0x95, 0xec, 0x0c, 0x61, 0x0d, 0x6d,         // ...
]

};

module.exports = helpers;

