#!/bin/bash
NAME=call
adb push $ANDROID_PRODUCT_OUT/system/bin/$NAME /data/
adb shell chmod 777 /data/$NAME
adb shell /data/$NAME $*
adb shell dmesg|grep scullc
