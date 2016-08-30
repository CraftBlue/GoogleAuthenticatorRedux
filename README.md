# Google Authenticator Redux PHP Client #

[![Build Status](https://travis-ci.org/CraftBlue/GoogleAuthenticatorRedux.png?branch=master)](https://travis-ci.org/CraftBlue/GoogleAuthenticatorRedux)

The library provides support for 2-Factor authentication, often referred to as **2FA**.

The client is intended to be used with the Google Authenticator mobile app
available on both Android and iOS devices. Google Authenticator is merely an implementation of 
the algorithm defined in [RFC6238](http://tools.ietf.org/html/rfc6238), better known as
**TOTP: Time-Based One-Time Password Algorithm**. 

The class contains methods which support:
 
 * The generation of RFC6238 compliant secret keys
 * The generation of Base32 codes based on the secret key
 * Creation of QR Code image URLs to present to the user for scanning into the Google Authenticator app
 * Validation of a user-submitted code against a known secret key

## Credits ##

This project is a full revamp of [PHPGangsta](http://www.phpgangsta.de/)'s original [GoogleAuthenticator](https://github.com/PHPGangsta/GoogleAuthenticator) repository
to promote best practices in PHP security and modern PSR-4 standards with Packagist.

Fixes and improvements include:

* Prevention of timing attacks
* Proper pseudo-random secret key generation
* Usage of safe string comparison functions
* Usage of a standardized Base32 library
* Improved examples and documentation
* Improved code comments to point out source of 
* Validation and sanitization of QR code labels
* Additional parameter support when generating QR codes 
* PSR-4 support

## Installation ##

The recommended way to install this library is through Composer.

```
# install composer if you don't already have it on your machine
curl -sS https://getcomposer.org/installer | php

# from your project's base directory, run the composer command to install GoogleAuthenticator
php composer.phar require craftblue/google-authenticator-redux
```

Ensure you require Composer's autoloader somewhere in your code:
```php
<?php

require 'vendor/autoload.php';
```

You'll now have access to autoload and use the client in your code:

```php
<?php

require 'vendor/autoload.php';

$client = new CraftBlue\GoogleAuthenticator();
```


To get any updates available from GoogleAuthenticator, you can always run:

```
php composer.phar update
```

## Example Code ##

```php
<?php

// if you are using composer, which is the preferred method of autoloading 
require_once('./vendor/autoload.php');

// create a new secret for a user wishing to enable 2FA
// you will need to store this securely
$secret = $ga->createSecret();

// example of generating a QR code to display to the end user 
// note that you need to generate a unique label for each user
// in the format of your application or vendor name (a namespace/prefix)
// followed by a colon, followed by a unique identifier for the user such
// as their login email address to your app or their name
$qrCodeUrl = $ga->getQRCodeUrl('MyVendorPrefix:userlogin@gmail.com', $secret);
echo '<img src="' . $qrCodeUrl . '" />';

// retrieve an example valid code
// (usually the user would supply this for you from the Google Authenticator app) 
$code = $ga->getCode($secret);

// example of verifying that a code is valid for the secret at this given time 
if ($ga->verifyCode($secret, $code, 2)) {
    echo 'VERIFIED';
} else {
    echo 'VERIFICATION FAILED';
}
```

## Live Demo ##

This project contains an `/example` directory which contains a working `index.php` demo. 
If you have PHP running on your machine, you can run the example code using
PHP's built in web server following these steps:

1. Checkout the repository, i.e. `git checkout ____`
1. Navigate to the `example/` directory
1. Start PHP's built in web server for the project by running the included bash script:  
   ```bash
   ./server.sh
   ```
1. Navigate your web browser to `http://127.0.0.1:8000` for the demo
1. View the source code of `index.php` to learn how the demo works

## Security Considerations ##

* Secret keys should never be exposed to end users on the client side
* Secret keys should be stored securely in your server-side code
* Secret keys should be unique to each user. Only generate one per user.
* It's recommended you two-way encrypt secret keys via tamper-resistant hardware encryption and 
expose them only when required. For example, you should only decrypt the secret key
when verifying the user-submitted OTP code/value. The secret key should be immediately
re-encrypted to limit exposure in your RAM.
* Your client and server should have CSRF protection to prevent against replay attacks.
* Implement rate limiting on your code verification endpoint with either exponential backoff delays
or forced CAPTCHAs to ensure users cannot brute force guess any codes.

## Running Tests ##

Depending on if you have PHPUnit available globally on your system or not, you can run the following:

```bash
# if you have phpunit globally, run this from the base project directory:
phpunit 

# after updating composer, run this from the base project directory:
vendor/bin/phpunit
```
