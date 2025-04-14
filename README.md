# `@aegisjsproject/otp`

An OTP library written using the `crypto` API

[![CodeQL](https://github.com/Aegisjsproject/otp/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Aegisjsproject/otp/actions/workflows/codeql-analysis.yml)
![Node CI](https://github.com/Aegisjsproject/otp/workflows/Node%20CI/badge.svg)
![Lint Code Base](https://github.com/Aegisjsproject/otp/workflows/Lint%20Code%20Base/badge.svg)

[![GitHub license](https://img.shields.io/github/license/Aegisjsproject/otp.svg)](https://github.com/Aegisjsproject/otp/blob/master/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/Aegisjsproject/otp.svg)](https://github.com/Aegisjsproject/otp/commits/master)
[![GitHub release](https://img.shields.io/github/release/Aegisjsproject/otp?logo=github)](https://github.com/Aegisjsproject/otp/releases)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/shgysk8zer0?logo=github)](https://github.com/sponsors/shgysk8zer0)

[![npm](https://img.shields.io/npm/v/@aegisjsproject/otp)](https://www.npmjs.com/package/@aegisjsproject/otp)
![node-current](https://img.shields.io/node/v/@aegisjsproject/otp)
![npm bundle size gzipped](https://img.shields.io/bundlephobia/minzip/@aegisjsproject/otp)
[![npm](https://img.shields.io/npm/dw/@aegisjsproject/otp?logo=npm)](https://www.npmjs.com/package/@aegisjsproject/otp)

[![GitHub followers](https://img.shields.io/github/followers/AegisJSProject.svg?style=social)](https://github.com/AegisJSProject)
![GitHub forks](https://img.shields.io/github/forks/Aegisjsproject/otp.svg?style=social)
![GitHub stars](https://img.shields.io/github/stars/Aegisjsproject/otp.svg?style=social)
[![Twitter Follow](https://img.shields.io/twitter/follow/shgysk8zer0.svg?style=social)](https://twitter.com/shgysk8zer0)

[![Donate using Liberapay](https://img.shields.io/liberapay/receives/shgysk8zer0.svg?logo=liberapay)](https://liberapay.com/shgysk8zer0/donate "Donate using Liberapay")
- - -

- [Code of Conduct](./.github/CODE_OF_CONDUCT.md)
- [Contributing](./.github/CONTRIBUTING.md)
<!-- - [Security Policy](./.github/SECURITY.md) -->

## Features

* Implements RFC 6238 for TOTP generation and verification.
* Uses the standard `Web Crypto API` for secure HMAC operations.
* Supports SHA-1, SHA-256, and SHA-512 algorithms.
* Provides Base32 encoding/decoding (RFC 4648 compatible).
* Generates and parses `otpauth://totp/` URIs for easy provisioning with authenticator apps.
* Cryptographically secure secret generation.
* Configurable token length, time period, and time skew tolerance.
* Pure ES Module, no external runtime dependencies for core crypto.

## Installation

### Using npm (for Node.js, Bundlers)

Install the package using your preferred package manager:

```bash
# Using npm
npm install @aegisjsproject/otp

# Using yarn
yarn add @aegisjsproject/otp

# Using pnpm
pnpm add @aegisjsproject/otp

# Using Git submodules
git submodule add https://github.com/Aegisjsproject/otp.git path/to/destination
```

### Using a CDN with [Importmap](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/script/type/importmap)

```html
<script type="importmap">
  {
    "imports": {
      "@aegisjsproject/otp": "https://unpkg.com/@aegisjsproject/otp[@vx.y.z]/otp.min.js",
      "@aegisjsproject/otp/": "https://unpkg.com/@aegisjsproject/otp[@vx.y.z]/"
    }
  }
</script>
```

## Usage Example

```js
import {
    generateSecret,
    secretToKey,
    createOTPAuthURI,
    generateTOTP,
    verifyTOTP,
    parseOTPAuthURI,
    // other exports if needed...
} from '@aegisjsproject/otp';

// Generate the random bytes
const secret = generateSecret();

// Create a secret key from those random bytes
const key = await secretToKey(secret);

// Generate an `otpauth:` URI to QR encode (QR encoding not provided)
const uri = createOTPAuthURI({ label: 'Acme:user@example.com', issuer: 'Acme', secret });

// Verify a user-provided TOTP code
const valid = await verifyTOTP(totpCode, key);
```
