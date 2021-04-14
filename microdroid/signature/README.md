# Microdroid Signature

Microdroid Signature contains the signatures of the payloads so that the payloads are
verified inside the Guest OS.

* APEX packages that are passed to microdroid should be listed in the Microroid Signature.

## Format

Microdroid Signature is composed of header and body.

| offset | size | description                                                    |
|--------|------|----------------------------------------------------------------|
| 0      | 4    | Header. unsigned int32: body length(L) in big endian           |
| 4      | L    | Body. A protobuf message. [schema](microdroid_signature.proto) |
