export TARGET_CODESIGN_FLAGS = -Sentitlements.xml
export TARGET = iphone:clang:latest:10.2
export ARCHS = arm64
#messages=yes
export COPYFILE_DISABLE=1

PACKAGE_VERSION=$(shell cat "$(THEOS_PROJECT_DIR)/version.txt")

include $(THEOS)/makefiles/common.mk

TOOL_NAME = SSHswitch
$(TOOL_NAME)_CFLAGS += -fvisibility=hidden -DBUILD_VERSION="\"$(PACKAGE_VERSION)\""
$(TOOL_NAME)_FILES = SSHswitch.c
$(TOOL_NAME)_INSTALL_PATH = /usr/bin/

include $(THEOS_MAKE_PATH)/tool.mk

