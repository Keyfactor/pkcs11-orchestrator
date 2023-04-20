## Use Case

The PKCS11 orchestrator extensions connects to a PKCS11 Library for a PKCS11-compatible device such as an HSM.
It implements the following capabilities:
1. Inventory - Return all certificates stored on the device accessible by the PIN provided
2. Reenrollment - Perform key generation on the device and create a new certificate with a CSR signed by the generated keys.

## PKCS11 Library and Device Configuration

The PKCS11 device needs to have a corresponding dotnet DLL provided to access it. The configuration of the device and library will be specific to the manufacturer.
A PIN will be used to logon to the device. The PIN used should not be the security officer PIN.
The User PIN provided should have permissions to Generate keys and perform Signings.

The PKCS11 library for the device should be copied and accessible somewhere in the filesystem relative to the Orchestrator. This location will be referenced in the `Store Path` in step two of the Extension Configuration.
Access permissions may need to be reviewed to ensure the Orchestrator can load the PKCS11 library.

## PKCS11 Orchestrator Extension Configuration

**1. Create the New Certificate Store Type for the PKCS11 orchestrator extension**

In Keyfactor Command create a new Certificate Store Type similar to the one below by clicking Settings (the gear icon in the top right) => Certificate Store Types => Add:

![](images/store-type-basic.png)


Leave other settings as default in Advanced and Custom Fields. Add a single Entry Parameter for the Label (Alias) below:

![](images/entry-parameter.png)

**2. Create a new PKCS11 Certificate Store**

After the Certificate Store Type has been configured, a new PKCS11 Certificate Store can be created. When creating the store set the following values:

| Certificate Store parameter | Value |
| - | - |
| Client Machine | Any display name for the store |
| Store Path | The absolute path to the PKCS11 library DLL |
| Store Password | The PIN to access the device |


The Client Machine is not used and can just be a helpful name for labeling the store. The Store Path should look like `C:\Program Files\manufacturer\device\device_pkcs11.dll`.

**3. (Optional) Generate a new key and Enroll a certificate**

Selecting Reenrollment for the store will trigger generation of a new key pair for creating a certificate. The Label (Alias) should be set with the name for the key pair which will also serve as the certificate's alias in Keyfactor.

### License
[Apache](https://apache.org/licenses/LICENSE-2.0)
