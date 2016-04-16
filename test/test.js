var chai = require("chai");
var sinon = require("sinon");
var sinonChai = require("sinon-chai");
var chaiAsPromised = require("chai-as-promised");
var Auth = require("../ctap-authenticator.js");

chai.use(sinonChai);
chai.use(chaiAsPromised);
var assert = chai.assert;
var should = chai.should();
var expect = chai.expect;

var authCmd = {
	rpId: "paypal.com",
	clientDataHash: 0x5a81483d96b0bc15ad19af7f5a662e14b275729fbc05579b18513e7f550016b1,
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
};

var authenticatorMakeCredentialCommandCbor = [
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
];

var helperAuth = {
	send: helperSend,
	receive: helperReceive
};

function helperSend(cborMsg, cb) {
	cb(null, cborMsg);
}

function helperReceive(cb) {
	var cborMsg = null;
	cb(null, cborMsg);
}

describe("Basic tests", function() {
	var sendSpy, receiveSpy;

	beforeEach(function() {
		sendSpy = sinon.spy(helperAuth, "send");
		receiveSpy = sinon.spy(helperAuth, "receive");
	});

	afterEach(function() {
		helperAuth.send.restore();
		helperAuth.receive.restore();
	});

	it("send message", function() {
		var a = new Auth(helperAuth);
		var p = a.sendMessage("1");
		assert.isFulfilled(p);
		assert(sendSpy.calledOnce, "send should have been called once");
	});

	it("receive message", function() {
		var a = new Auth(helperAuth);
		var p = a.receiveMessage();
		assert.isFulfilled(p);
		assert(receiveSpy.calledOnce, "receive should have been called once");
	});

	it("send simple message", function() {
		var a = new Auth(helperAuth);
		var p = a.sendMessage("1");
		return p.should.eventually.satisfy(function(b) {
			return b.equals(new Buffer([0x1]));
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
		});
	});

	it("send moderately complex message", function() {
		var a = new Auth(helperAuth);
		var p = a.sendMessage(JSON.stringify({
			foo: "bar"
		}));
		return p.should.eventually.satisfy(function(b1) {
			var b2 = new Buffer([
				0xa1, // map(1)
					0x63, // text(3)
						0x66, 0x6f, 0x6f, // "foo"
					0x63, // text(3)
						0x62, 0x61, 0x72, // "bar"
				]);
			return b1.equals(b2);
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
		});
	});

	it("send real message", function() {
		var a = new Auth(helperAuth);
		var p = a.authenticatorMakeCredential(
			authCmd.rpId,
			authCmd.clientDataHash,
			authCmd.account,
			authCmd.cryptoParameters
		);
		return p.should.eventually.satisfy(function(b1) {
			var b2 = new Buffer(authenticatorMakeCredentialCommandCbor);
			// console.log ("Buffer Received:"); 
			// require ("hex")(b1);
			// console.log ("Buffer Expected:");
			// require ("hex")(b2);
			// console.log (require ("diff-buf") (b1, b2));
			return b1.equals(b2);
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
		});
	});

	it("authenticatorMakeCredential missing rpId");
	it("authenticatorMakeCredential missing clientDataHash");
	it("authenticatorMakeCredential missing account");
	it("authenticatorMakeCredential missing cryptoParameters");
	it("authenticatorMakeCredential with blacklist");
	it("authenticatorMakeCredential with extensions");

	it("receive right message");
});