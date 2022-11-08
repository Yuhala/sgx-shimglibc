# sgx-shimglibc
Intel SGX SDK compatible glibc shim library for SGX enclave projects.


## Install Intel SGX SDK and driver on your system
- Run the `sgx-install` script included in this repo.
```
./sgx-install.sh

```
- After installation, activate some SGX SDK environment variables.
```
source /opt/intel/sgxsdk/environment

```

## Build and test a sample application
- To run full C/Cpp application inside the enclave with the shim library, add the application's source and header files inside the `Enclave/enc-app` folder, as shown in the example application files included.
- The main entry point of your application should have the name `run_main`. This is the function called by `ecall_run_main` once the enclave application is run.
- Also, the makefile is configured in such a way as to search for your application's in-enclave source files in the `Enclave/enc-app` folder.
- If you wish to re-architecture your application differently that's great, but you are on your own :)).
