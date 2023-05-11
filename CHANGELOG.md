1.0.0
- Initial release
- Support Inventory to find all certificates on the first available Slot
- Support Reenrollment to generate a new keypair on device
- Keypair is used to sign a CSR, submit to Keyfactor and enroll a new certificate, which is loaded to the device
    - RSA keys use keysize 2048, SHA256
    - EC keys use curve P-256, SHA256