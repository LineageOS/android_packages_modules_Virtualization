# Microdroid Payload

Payload disk is a composite disk image referencing host APEXes and an APK so that microdroid
mounts/activates APK/APEXes and executes a binary within the APK.

## Partitions

Payload disk has 1 + N(number of APEX/APK payloads) partitions.

The first partition is a "payload-metadata" partition which describes other partitions.
And APEXes and an APK are following as separate partitions.

For now, the order of partitions are important.

* partition 1: Metadata partition
* partition 2 ~ n: APEX payloads
* partition n + 1: APK payload

It's subject to change in the future, though.

### Metadata partition

Metadata partition provides description of the other partitions and the location for VM payload
configuration.

The partition is a protobuf message prefixed with the size of the message.

| offset | size | description                                                    |
|--------|------|----------------------------------------------------------------|
| 0      | 4    | Header. unsigned int32: body length(L) in big endian           |
| 4      | L    | Body. A protobuf message. [schema](metadata.proto) |

### Payload partitions

Each payload partition presents APEX or APK passed from the host.

At the end of each payload partition the size of the original payload file (APEX or APK) is stored
in 4-byte big endian.

For example, the following code shows how to get the original size of host apex file
when the apex is read in microdroid as /dev/block/vdc2,

    int fd = open("/dev/block/vdc2", O_RDONLY | O_BINARY | O_CLOEXEC);
    uint32_t size;
    lseek(fd, -sizeof(size), SEEK_END);
    read(fd, &size, sizeof(size));
    size = betoh32(size);

## How to Create

### `mk_payload`

`mk_payload` creates a payload composite disk image as described in a JSON which is intentionlly
similar to the schema of VM payload config.

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
  ],
  "apk": {
    "name": "com.my.world",
    "path": "/path/to/world.apk"
  }
}
$ adb push payload_config.json hello.apex /data/local/tmp/
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/mk_payload payload_config.json payload.img
$ adb shell ls /data/local/tmp/*.img
payload.img
payload-footer.img
payload-header.img
payload-metadata.img
payload.img.0          # fillers
payload.img.1
...
```

In the future, [VirtualizationService](../../virtualizationservice) will handle this.
