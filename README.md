# Confidential Package Manager (CPM)

The Confidential Package Manager is a Trusted Application (TA) intented to be deployed by a system integrator, and can be used to deploy OP-TEE applications without being tied to the OP-TEE credentials.

It allows deployment of trusted (signed) and (confidential) encrypted applications, re-keying them when they are stored in Confidential storage.

A companion application ([cpm-tool](https://github.com/EnclaveDeviceBlueprint/ConfidentialPackageTools)) is need to provide connectivity to a key-store back-end, and injecting the keys needed for decryping the applications.


The Host/TA interface is defined with openenclave, and detailed in the [Confidential Pakage Specification](https://github.com/EnclaveDeviceBlueprint/ConfidentialPackageSpecification)
The build will generate the openenclave files during the build process

 **This application is still in the prototyping stage, and not ready for production**
 
 ## Building the CPM
 The CPM has has a dependency to the OpenEnclave SDK matching the target device. For now we assume this is provides
 ```
 # Configure the build (this assumes an out of tree build, by creating a build directory in the source directory)
 cmake \
     -DOE_PACKAGE_OPTEE_PLATFORM=trustsom \
     -DCMAKE_TOOLCHAIN_FILE=../cmake/arm-cross.cmake \
     -DCMAKE_BUILD_TYPE=Debug \
     -DOE_PACKAGE_PREFIX=<<path to openenclave sdk>> \
     -DCPS_DIR=<<path to confidential packaging specification>> \
     ..
 
 # build the application, and an incomplete host test application
 make
 ```
