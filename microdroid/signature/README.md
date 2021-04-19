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

## How to Create

### `mk_microdroid_signature` and `mk_cdisk`

For testing purpose, use `mk_microdroid_signature` to create a Microdroid Signature.

```
$ cat signature_config.json
{
  "apexes": [
    {
      "name": "com.my.hello",
      "path": "hello.apex"
    }
  ]
}
$ adb push signature_config.json hello.apex /data/local/tmp/
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/mk_microdroid_signature signature_config.json signature
```

Then, pass the signature as the first partition of the payload disk image.

```
$ cat payload_cdisk.json
{
  "partitions": [
    {
      "label": "signature",
      "path": "signature"
    },
    {
      "label": "com.my.hello",
      "path": "hello.apex"
    }
  ]
}
$ adb push payload_cdisk.json /data/local/tmp/
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/mk_cdisk payload_cdisk.json payload.img
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/crosvm .... --disk=payload.img'
```

### `mk_payload`

`mk_payload` combines these two steps into a single step. Additionally, `mk_payload` can search system APEXes as well.
This will generate the output composite image as well as three more component images. (See below)

```
$ cat payload_config.json
{
  "system_apexes": [
    "com.android.adbd",
  ],
  "apexes": [
    {
      "name": "com.my.hello",
      "path": "hello.apex"
    }
  ]
}
$ adb push payload_config.json hello.apex /data/local/tmp/
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/mk_payload payload_config.json payload.img
$ adb shell ls /data/local/tmp/*.img
payload-footer.img
payload-header.img
payload-signature.img
payload.img
```

In the future, [VirtManager](../../virtmanager) will handle these stuffs.