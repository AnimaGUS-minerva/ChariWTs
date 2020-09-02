# Where do these test files come from

## jrc_prime256v1.crt, jrc_prime256v1.key, certs.crt, update-certs

The file update-certs creates certs.crt.
It takes files jrc_prime256v1.crt and jrc_prime256v1.key from an adjacent "fountain" installation.

It previously included:  masa_secp384r1.crt, masa_secp384r1.key, ownerca_secp384r1.crt

# voucher_jada123456789.vch

This is produced by "vch voucher should sign a voucher in COSE format", which is voucher_spec.rb,
around line 139.

# voucher_jada123456789.bag.pretty, voucher_jada123456789.diag, voucher_jada123456789.pretty

These are used by some tests and are references stored into tmp.

# vr_00-D0-E5-F2-00-02.vrq

This example voucher request comes from operating the reach/fountain/highway tests using a specific keypair.
The script in fountain, spec/curltest/07-update-constrained-request-03.sh invokes the adjacent reach
toolkit to generate a new voucher request.

# not yet categorized

voucher_jada123456789_bad.vch
010009-idevid.pem
jada123456789.json
jada123456789.json_u
JADA345768912.bag.pretty
JADA345768912.example.json
JADA345768912.pretty
jada_prime256v1.crt
jada_prime256v1.key
json_voucher1.json
parboiled_jada56789012.txt
parboiled_vr-9730-siemens-bt.pkcs
pledge_jada123456789.diag
pledge_jada345768912.diag
pledge_prime256v1.crt
pledge_request01.pkcs
siemens-bt-reg29.pkcs
siemens-bt-registrar.pem
thing_f2-00-99.txt
thing_f2-01-99.txt
voucher_nice23465789.bag.pretty
voucher_nice23465789.pretty
voucher_request-00-D0-E5-03-00-03.pkcs
voucher_request1-anchor.pem
voucher_request1.jwt
voucher_request1.pkix
voucher_request-bt01.pkcs

