# fido2-authenticator
A utility for communicating with FIDO 2.0 authenticators using the Client to Authenticator Protocol (CTAP)

## Install

``` bash
npm install fido2-authenticator
```

## Command Line

## API
The Authenticator object has the following methods:
* authenticatorMakeCredential
* authenticatorGetAssertion _(currently not implemented)_
* authenticatorCancel _(currently not implemented)_
* authenticatorGetInfo _(currently not implemented)_
* sendMessage
* receiveMessage

### Auth
The auth constructor takes the form: `new Auth(sendFunction, receiveFunction)` where `sendFunction` and `receiveFunction` are called when the `Auth` needs to send / receive data to / from the underlying implementation.

``` js
function sendMessage (cbor, cb);
function receiveMessage (cbor, cb);
// cbor = cbor encoded message
// cb = callback function for when sending is complete
```

## Notes
Currently incomplete:
* Doesn't support `rawAttestation` parameter in `makeCredential` response
* Doesn't support `getAttestation`
* Doesn't support `cancel`
* Doesn't support `getInfo`
