# Microdroid demo app

## Building

```
TARGET_BUILD_APPS=MicrodroidDemoApp m apps_only dist
```

## Installing

```
adb install out/dist/MicrodroidDemoApp.apk
adb shell mkdir /data/local/tmp/virt
adb push out/dist/MicrodroidDemoApp.apk.idsig /data/local/tmp/virt/
```

## Running

Run the app by touching the icon on the launcher. Press the `run` button to
start a VM. You can see console output from the VM on the screen. You can stop
the VM by pressing the `stop` button.
