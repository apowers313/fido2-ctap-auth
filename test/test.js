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
		sendSpy = sinon.spy(helpers, "send");
		receiveSpy = sinon.spy(helpers, "receive");
		helpers.clearNextResponseErr();
	});

	afterEach(function() {
		helpers.send.restore();
		helpers.receive.restore();
		helpers.clearLastMsg();
	});

	it("send message", function() {
		var a = new Auth(helpers.send, helpers.receive);
		var p = a.sendMessage("1");
		assert.isFulfilled(p);
		assert(sendSpy.calledOnce, "send should have been called once");
	});

	it("receive message", function() {
		var a = new Auth(helpers.send, helpers.receive);
		var p = a.receiveMessage();
		assert.isFulfilled(p);
		assert(receiveSpy.calledOnce, "receive should have been called once");
	});

	it("send simple message", function() {
		var a = new Auth(helpers.send, helpers.receive);
		var p = a.sendMessage("1");
		return p.should.eventually.satisfy(function(b) {
			return helpers.typedArrayEquals (b, Uint8Array.from([1]));
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
		});
	});

	it("send moderately complex message", function() {
		var a = new Auth(helpers.send, helpers.receive);
		var p = a.sendMessage(JSON.stringify({
			foo: "bar"
		}));
		return p.should.eventually.satisfy(function(b1) {
			var b2 = Uint8Array.from([
				0xa1, // map(1)
					0x63, // text(3)
						0x66, 0x6f, 0x6f, // "foo"
					0x63, // text(3)
						0x62, 0x61, 0x72, // "bar"
			]);
			return helpers.typedArrayEquals(b1, b2);
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
		});
	});

	it("makeCredential", function() {
		var a = new Auth(helpers.send, helpers.receive);
		var p = a.authenticatorMakeCredential(
			helpers.makeCredArgs.rpId,
			helpers.makeCredArgs.clientDataHash,
			helpers.makeCredArgs.account,
			helpers.makeCredArgs.cryptoParameters
		);
		return p.should.eventually.satisfy(function(ret) {
			// var cert = new Buffer(helpers.derEccPublicKey).toString("hex");
			// console.log ("Buffer Received:"); 
			// require ("hex")(ret);
			// console.log ("Buffer Expected:");
			// require ("hex")(b2);
			// console.log (require ("diff-buf") (b1, b2));
			return ret.should.eql(helpers.makeCredResp);
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
			assert(receiveSpy.calledOnce, "receive should have been called once");
		});
	});

	it("authenticatorMakeCredential missing rpId");
	it("authenticatorMakeCredential missing clientDataHash");
	it("authenticatorMakeCredential missing account");
	it("authenticatorMakeCredential missing cryptoParameters");
	it("authenticatorMakeCredential with blacklist");
	it("authenticatorMakeCredential with extensions");

	it("authenticatorGetAssertion", function() {
		var a = new Auth(helpers.send, helpers.receive);
		var p = a.authenticatorGetAssertion(
			helpers.makeCredArgs.rpId,
			helpers.makeCredArgs.clientDataHash
		);
		return p.should.eventually.satisfy(function(ret) {
			// var cert = new Buffer(helpers.derEccPublicKey).toString("hex");
			// console.log ("Buffer Received:"); 
			// require ("hex")(ret);
			// console.log ("Buffer Expected:");
			// require ("hex")(b2);
			// console.log (require ("diff-buf") (b1, b2));
			return ret.should.eql(helpers.getAssertResp);
		}).then(function(res) {
			assert(sendSpy.calledOnce, "send should have been called once");
			assert(receiveSpy.calledOnce, "receive should have been called once");
		});
	});

	it("authenticatorGetInfo");
	it("authenticatorCancel");
	it("handles error response");
	it("authenticatorMakeCredential handles error response");
	it("authenticatorGetAssertion handles error response");

	it("receive right message");
});