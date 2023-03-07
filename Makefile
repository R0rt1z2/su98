# Android
NDK_BUILD := NDK_PROJECT_PATH=. ndk-build NDK_APPLICATION_MK=./Application.mk

# Retrieve binary name from Android.mk
BIN := $(shell cat Android.mk | grep LOCAL_MODULE  | head -n1 | cut -d' ' -f3)

# Out folder, where binaries are built to
BIN_PATH := libs/arm64-v8a/$(BIN)

$(BIN_PATH):
	$(NDK_BUILD)

clean:
	$(NDK_BUILD) clean