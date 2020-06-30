# README for POC of certificateless encryption and signing
### Author : Mickael Bonjour

## Purpose of this
This readme is here to help building the POC from sources and explain a bit what it's doing.
## Dependencies
Libsodium need to be installed prior to the build of the project.
## Build and launch
To simply build from the sources you can try this command :
```bash
cmake . && make
```
And you will have an ELF executable called Test_RELIC.

## Purpose of the POC
The POC simply try to encrypt an AES Key with Certificateless crypto and then sign it.
Then it will encrypt a message using the AES Key. It's simply a POC, so no memory is cleaned for the AES Key, and some vulnerabilities can appear at this point.
But the POC proves just that certificateless crypto is quick and can be implemented to encrypt messages.
