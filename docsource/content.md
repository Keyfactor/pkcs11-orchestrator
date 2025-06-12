## Overview

This Orchestrator Extension allows for interacting with PKCS11-compatible devices to inventory certificates and enroll new certificates with on-device key generation via a reenrollment job.

The PKCS11 orchestrator extensions connects to a PKCS11 Library for a PKCS11-compatible device such as an HSM.
It implements the following capabilities:
1. Inventory - Return all certificates stored on the device accessible by the PIN provided
2. Reenrollment - Perform key generation on the device and create a new certificate with a CSR signed by the generated keys.

## Requirements

The PKCS11 device needs to have a corresponding dotnet DLL provided to access it. The configuration of the device and library will be specific to the manufacturer.
A PIN will be used to logon to the device. The PIN used should not be the security officer PIN.
The User PIN provided should have permissions to Generate keys and perform Signings.

The PKCS11 library for the device should be copied and accessible somewhere in the filesystem relative to the Orchestrator. This location will be referenced in the `Store Path` in step two of the Extension Configuration.
Access permissions may need to be reviewed to ensure the Orchestrator can load the PKCS11 library.
