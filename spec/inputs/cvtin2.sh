#!/bin/bash

# this converts cose2.cdiag to ctxt.

. /etc/profile.d/rvm.sh
rvm use 2.1.5
diag2cbor.rb < cose2.cdiag >cose2.bin
cbor2pretty.rb <cose2.bin  >cose2.ctxt

