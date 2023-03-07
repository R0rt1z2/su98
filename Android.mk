LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := su98
LOCAL_SRC_FILES := su98.c

LOCAL_CFLAGS += \
    -Wall \
    -pedantic

include $(BUILD_EXECUTABLE)

$(call import-add-path, $(LOCAL_PATH))
