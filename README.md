ccnumber
========

A data type representing encrypted credit card numbers (or anything else
that is sensitive and needs to be stored encrypted in the database).

The primary idea is offloading operations to a trusted component (running
on a different machine, in a SGX/TrustZone, or just a different process),
so that the database never sees plaintex data directly.  The offloading
allows the database to perform useful operations (index searches, ...) on
the encrypted data, without a risk of leaking the decrypted data.

This is a PoC project, demonstrating the idea and possibilities. The code
implements a minimal functionality, is inefficient in various ways, and
generally untested.


Crypto
------

All the crypto is done using libsodium [1], an implementation of NaCl [2].
This does not solve the issue of key management, though.  In this PoC the
key is hard-coded, but obviously that's not production-ready.

The encryption does have overhead, both in terms of disk space and CPU.
Encryption makes each value 40B longer (nonce + MAC), and makes it look
random (and thus non-compressible). The CPU usage is due to having to
decrypt the values before performing operations.


Components
----------

s


Possible improvements
---------------------


1) communication overhead

The communication between PostgreSQL and the trusted component happens
over regular TCP. While this is flexible and allows running the comparator
on a separate host, it's not particularly efficient.  Using a different
communication protocol (e.g. shared-memory IPC) should reduce the overhead
significantly.


2) hash support

The current data type supports only comparison operations, i.e. sorting.
Adding hash support is possible and fairly straight-forward (send data
to trusted component and make it reply with a hash).

The question is how much this would weaken the encryption, because each
hash value leaks a bit of information about the value.  However, using
a keyed-hash function (i.e. HMAC), possibly with a separate key, should
not leak any additional information, compared to the comparisons.

The hash might even be stored with the value itself, eliminating some of
the remote operations in various cases entirely.  As it might be stored
in hash indexes anyway, that does not seem like a major issue.


3) ordering

B-tree indexes inherently leak information about ordering.  The question
is whether the values have some natural ordering worth preserving, or
whether the ordering is needed merely for grouping etc.  For card numbers
we usually use lexicographic ordering, but there's nothing particularly
meaningful about that - we usually sort the data by something else when
showing them to users.  So we can use any other ordering, as long as it's
sane enough to support GROUP BY.  For example we may use the hash value,
which would eliminate most of the remote comparisons (to cases where the
hashes are equal).


4) other operations and/or aggregates

Depending on the data type, it's possible to support additional operations
and aggregates. For example for numeric types it'd make sense to support
addition or the usual aggregates.  All it'd take is extending the trusted
component to support these operations.  For the aggregates, it's possible
to do batching (accumulating multiple encrypted values and only then pass
them to the trusted component) to reduce communication overhead.

Before implementing each operation, it's important to consider if it may
leak valuable informatio.  Generally, operations processing and producing
only encrypted data are safe.  But for example allowing "pattern matching"
on encrypted data (with plaintext patterns) is unsafe, as the users may
learn valuable information even without having the secret key (assuming
they can communicate with the trusted component).


5) ARM TrustZone, Intel SGX

One quite attractive option is running the trusted component on the same
host, in an isolated environment.  Both Intel and ARM have technologies
(SGX/TrustZone) meant to allow this.  Another option would be to run the
trusted component on a special-purpose device (essentially HSM) connected
to the host, depending on how programmable those are.

It might be possible to implement custom HSM on devices like usbarmory [3].


[1] https://download.libsodium.org/doc/
[2] http://nacl.cr.yp.to/
[3] https://inversepath.com/usbarmory.html
