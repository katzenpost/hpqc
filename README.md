# HPQC

## hybrid post quantum cryptography

we have but two simple goals at the moment:

1. silo ALL of the katzenpost cryptography into this one library so that it's easier to audit,
easier to reason about. This will help us standardize our approach to solving cryptographic problems
across multiple protocols.
2. Provide a very niche cryptography library that other golang software projects can use if they
want hybrid constructions consisting of classical and post quantum cryptographic primitives.


* hybrid KEMs
* hybrid NIKEs
* hybrid signature schemes

# licensing

this is agpl-3 licensed code however some modules written by other authors
is included here and in those cases we've included their LICENSE file in the
directory or in the top comment of the file.
