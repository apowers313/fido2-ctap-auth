var chai = require("chai");
var sinon = require("sinon");
var sinonChai = require("sinon-chai");
var chaiAsPromised = require("chai-as-promised");
var Auth = require("../ctap-authenticator.js");
var helpers = require("./helpers/helpers.js");

chai.use(sinonChai);
chai.use(chaiAsPromised);
var assert = chai.assert;
var should = chai.should();
var expect = chai.expect;

describe("Basic tests", function() {
	var sendSpy, receiveSpy;

	beforeEach(function() {
		sendSpy = sinon.spy(helpers.helperAuth, "send");
		receiveSpy = sinon.spy(helpers.helperAuth, "receive");
	});

	afterEach(function() {
		helpers.helperAuth.send.restore();
		helpers.helperAuth.receive.restore();
	});

	it("send message", function() {
		var a = new Auth(helpers.helperAuth);
		var p = a.sendMessage("1");
		assert.isFulfilled(p);
		assert(sendSpy.calledOnce, "send should have been called once");
	});

	it("receive message", function() {
		var a = new Auth(helpers.helperAuth);
		var p = a.receiveMessage();
		assert.isFulfilled(p);
		assert(receiveSpy.calledOnce, "receive should have been called once");
	});

	it("send simple message", function() {
		var a = new Auth(helpers.helperAuth);
		var p = a.sendMessage("1");
		return p.should.eventually.satisfy(function(b) {
			return b.equals(new Buffer([0x1]));
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
		});
	});

	it("send moderately complex message", function() {
		var a = new Auth(helpers.helperAuth);
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
		var a = new Auth(helpers.helperAuth);
		var p = a.authenticatorMakeCredential(
			helpers.authCmd.rpId,
			helpers.authCmd.clientDataHash,
			helpers.authCmd.account,
			helpers.authCmd.cryptoParameters
		);
		return p.should.eventually.satisfy(function(b1) {
			var b2 = new Buffer(helpers.authenticatorMakeCredentialCommandCbor);
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
	it("authenticatorGetAssertion");
	it("authenticatorGetInfo");
	it("authenticatorCancel");

	it("receive right message");
});