# README

## OPENSSL cert

### Generate a self-signed SSL certificate using the OpenSSL
openssl req -newkey rsa:2048 -nodes -keyout crypto-enc.key -x509 -days 365 -out crypto-enc.pem

### Combine your key and certificate in a PKCS#12 (P12) bundle:
openssl pkcs12 -inkey crypto-enc.key -in crypto-enc.pem -export -out certificate.p12


## Test

``` bash
ruby hyb-crypto.rb 
ruby aes-crypto.rb
ruby rsa-crypto.rb
```



