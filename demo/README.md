# Microdroid demo app

## Building

```
TARGET_BUILD_APPS=MicrodroidDemoApp m apps_only dist
```

## Installing

```
adb install out/dist/MicrodroidDemoApp.apk
adb shell pm grant com.android.microdroid.demo android.permission.MANAGE_VIRTUAL_MACHINE
```

## Running

Run the app by touching the icon on the launcher. Press the `run` button to
start a VM. You can see console output from the VM on the screen. You can stop
the VM by pressing the `stop` button.
