# ChariWTs

This is a BRSKI voucher processor.  It was originally focused
on creating and processing vouchers expressed in CBOR Web Token (CWT)
format.

In has first evolved to support PKCS7 signed JSON as specified by
    https://datatracker.ietf.org/doc/draft-ietf-anima-voucher/
and https://datatracker.ietf.org/doc/draft-ietf-anima-bootstrapping-keyinfra/

It currently also supports encoding in JWT rather than PKCS7.
It will begin to support CWT encoded vouchers.

This uses rvm, ruby 2.4.1.
It requires a patch to the openssl extension which is currently at:
   https://github.com/ruby/openssl/pull/141

The name ChariWT is chosen to sound like "chariot", but have the
sequence "C" "W" and "T" in it.


 