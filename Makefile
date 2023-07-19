export TARGET_CODESIGN_FLAGS = -Sentitlements.xml
export TARGET = iphone:clang:10.2:10.2
export ARCHS = arm64
#messages=yes
export COPYFILE_DISABLE=1

PACKAGE_VERSION=$(shell cat "$(THEOS_PROJECT_DIR)/version.txt")

export THEOS_PACKAGE_SCHEME = $(if $(RF),rootful,rootless)
export THEOS_PACKAGE_INSTALL_PREFIX = /var/jb
# ^ using this for older Theos, sort of backporting from post 2023-03-26 Theos (which sets this var automatically).

ifneq ($(THEOS_PACKAGE_SCHEME),rootless)
# reset the jb root prefix for rootful
export THEOS_PACKAGE_INSTALL_PREFIX =
endif

include $(THEOS)/makefiles/common.mk

TOOL_NAME = SSHswitch
$(TOOL_NAME)_CFLAGS += -fvisibility=hidden -DBUILD_VERSION="\"$(PACKAGE_VERSION)\""
$(TOOL_NAME)_FILES = SSHswitch.c
$(TOOL_NAME)_INSTALL_PATH = $(THEOS_PACKAGE_INSTALL_PREFIX)/usr/bin/

# control file which we make in before-stage:: (want to make sure the arch is right, whatever was last manually written there)
_THEOS_DEB_PACKAGE_CONTROL_PATH = "$(THEOS_PROJECT_DIR)/control-$(THEOS_PACKAGE_SCHEME)"

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
ifneq ($(THEOS_PACKAGE_ARCH),iphoneos-arm64)
# so this must be some older (pre 2023-03-26) Theos, need to mangle things a bit when packaging. 

# for the filename and for the arch in before-stage::
THEOS_PACKAGE_ARCH = iphoneos-arm64

before-package::
# some backporting from Theos makefiles/package/deb.mk post 2023-03-26 internal-package::
	$(ECHO_NOTHING)mkdir -p "$(THEOS_STAGING_DIR)$(THEOS_PACKAGE_INSTALL_PREFIX)"$(ECHO_END)
	$(ECHO_NOTHING)rsync -a "$(THEOS_STAGING_DIR)/" "$(THEOS_STAGING_DIR)$(THEOS_PACKAGE_INSTALL_PREFIX)" --exclude "DEBIAN" --exclude "$(THEOS_PACKAGE_INSTALL_PREFIX)" $(_THEOS_RSYNC_EXCLUDE_COMMANDLINE) $(ECHO_END)
	$(ECHO_NOTHING)find "$(THEOS_STAGING_DIR)" -mindepth 1 -maxdepth 1 ! -name DEBIAN ! -name "var" -exec rm -rf {} \;$(ECHO_END)
	$(ECHO_NOTHING)rmdir "$(THEOS_STAGING_DIR)$(THEOS_PACKAGE_INSTALL_PREFIX)/var" >/dev/null 2>&1 || true$(ECHO_END)

endif
endif

before-stage::
	$(ECHO_NOTHING)sed -e 's/Architecture: iphoneos-arm.?.?/Architecture: $(THEOS_PACKAGE_ARCH)/' "$(THEOS_PROJECT_DIR)/control" > "$(THEOS_PROJECT_DIR)/control-$(THEOS_PACKAGE_SCHEME)"$(ECHO_END)
	$(ECHO_NOTHING)rm -rf $(THEOS_PROJECT_DIR)/layout/usr $(THEOS_PROJECT_DIR)/layout/var$(ECHO_END)
	$(ECHO_NOTHING)$(THEOS_PROJECT_DIR)/doc/makeDoc.sh$(ECHO_END)

after-stage::
	$(ECHO_NOTHING)find $(THEOS_STAGING_DIR) -name .DS_Store | xargs rm -rf$(ECHO_END)
	$(ECHO_NOTHING)find $(THEOS_STAGING_DIR) -name "*~" | xargs rm -f$(ECHO_END)
	$(ECHO_NOTHING)chmod 6755 $(THEOS_STAGING_DIR)$(THEOS_PACKAGE_INSTALL_PREFIX)/usr/bin/$(TOOL_NAME)$(ECHO_END)

after-package::
	$(ECHO_NOTHING)rm -f "$(THEOS_PROJECT_DIR)/control-$(THEOS_PACKAGE_SCHEME)" >/dev/null || true$(ECHO_END)

include $(THEOS_MAKE_PATH)/tool.mk

