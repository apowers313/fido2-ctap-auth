# fido2-authenticator
A utility for communicating with FIDO 2.0 authenticators using the Client to Authenticator Protocol (CTAP)

## Install

``` bash
npm install fido2-authenticator
```

## Usage

## API
authenticatorMakeCredential
authenticatorGetAssertion
sendRawMessage

registerAuthenticator (auth, options)
auth can be string to register a [ffi](https://github.com/node-ffi/node-ffi) library (currently unsupported)
auth can be an object with the following structure:

``` js
{
    sendMessage: sendMessage,
    receiveMessage: receiveMessage
}

function sendMessage (cbor, cb);
function receiveMessage (cbor, cb);
// cbor = cbor encoded message
// cb = callback function for when sending is complete
```