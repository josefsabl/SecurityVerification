Arachne/SecurityVerification
====

[![Build Status](https://img.shields.io/travis/Arachne/SecurityVerification/master.svg?style=flat-square)](https://travis-ci.org/Arachne/SecurityVerification/branches)
[![Coverage Status](https://img.shields.io/coveralls/Arachne/SecurityVerification/master.svg?style=flat-square)](https://coveralls.io/github/Arachne/SecurityVerification?branch=master)
[![Latest stable](https://img.shields.io/packagist/v/arachne/security-verification.svg?style=flat-square)](https://packagist.org/packages/arachne/security-verification)
[![Downloads this Month](https://img.shields.io/packagist/dm/arachne/security-verification.svg?style=flat-square)](https://packagist.org/packages/arachne/security-verification)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/Arachne/SecurityVerification/blob/master/license.md)

Installation
----

The best way to install Arachne/SecurityVerification is using [Composer](http://getcomposer.org/):

```sh
composer require arachne/security-verification
```

Now you need to register the extension using your [neon](https://ne-on.org) config file.

```neon
extensions:
    arachne.securityVerification: Arachne\SecurityVerification\DI\SecurityVerificationExtension
```
