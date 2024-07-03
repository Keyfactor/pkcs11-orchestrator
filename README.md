<h1 align="center" style="border-bottom: none">
    PKCS11 Universal Orchestrator Extension
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/pkcs11-orchestrator/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/pkcs11-orchestrator?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/pkcs11-orchestrator?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/pkcs11-orchestrator/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=orchestrator">
    <b>Related Integrations</b>
  </a>
</p>


## Overview

The PKCS11 Universal Orchestrator extension connects to PKCS11-compatible devices, such as Hardware Security Modules (HSMs), through their respective PKCS11 libraries. This extension facilitates the remote management of cryptographic certificates stored on these devices, leveraging Keyfactor Command to perform certificate operations. By using the PKCS11 extension, administrators can perform tasks such as inventorying current certificates and reenrolling certificates by generating new keys on the device. PKCS11 is a standard interface used for managing cryptographic tokens, enabling secure storage and management of digital certificates and keys. This ensures that cryptographic operations are handled in a secure, tamper-proof manner provided by the physical and logical protections of the HSM.

## Compatibility

This integration is compatible with Keyfactor Universal Orchestrator version  and later.

## Support
The PKCS11 Universal Orchestrator extension is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 
 
> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Installation
Before installing the PKCS11 Universal Orchestrator extension, it's recommended to install [kfutil](https://github.com/Keyfactor/kfutil). Kfutil is a command-line tool that simplifies the process of creating store types, installing extensions, and instantiating certificate stores in Keyfactor Command.


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Universal Orchestrator extensions](https://github.com/orgs/Keyfactor/repositories?q=orchestrator).