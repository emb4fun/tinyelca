# README for TinyELCA
"To enable HTTPS on your website, you need to get a certificate (a type of file) from a 
Certificate Authority (CA). Let’s Encrypt is a CA. In order to get a certificate for your 
website’s domain from Let’s Encrypt, you have to demonstrate control over the domain. 
With Let’s Encrypt, you do this using software that uses the ACME protocol which typically 
runs on your web host." (Source: Let’s Encrypt)

Let’s Encrypt is a great thing and has brought security to many websites through ease of 
use. The certificates from Let’s Encryped are also used for this website. Unfortunately can 
Let’s Encrypt only be used for domains which are accessible over the internet.

TinyELCA is an Embedded Local Certification Authority and tries to bring the HTTPS 
functionality to the local intranet.

More information are available here: 
https://www.emb4fun.de/projects/telca/index.html

# Some notes about Mbed TLS
Mbed TLS is used in .\source\common\library\mbedtls and was copied from the following project:
https://github.com/ARMmbed/mbedtls