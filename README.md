rsa_sig2n
=========

The repository contains:

* Experimental code to calculate RSA public keys based on two known message-signature pairs (based on https://crypto.stackexchange.com/questions/30289/is-it-possible-to-recover-an-rsa-modulus-from-its-signatures/30301#30301)
* Code to extract and generate RSA and HMAC signatures for JWTs
* Proof-of-Concept code to exploit the [CVE-2017-11424](https://snyk.io/vuln/SNYK-PYTHON-PYJWT-40693) key confusion vulnerability in pyJWT, without knowing the public key of the target

Additional reading: [Abusing JWT Public Keys Without the Public Key](https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/)

__You probably want to use the Docker image provided in the _standalone_ directory.__
