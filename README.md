Confidential Package Manager (CPM)
=================

The Confidential Package Manager is a Trusted Application (TA) intented to be deployed by a system integrator, and can be used to deploy OP-TEE applications without being tied to the OP-TEE credentials.

It allows deployment of trusted (signed) and (confidential) encrypted applications, re-keying them when they are stored in Confidential storage.

A companion application (Confidential Package Installer: CPI) is need to provide connectivity to a key-store back-end, and injecting the keys needed for decryping the applications.
