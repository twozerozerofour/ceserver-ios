TARGET := iphone:clang:latest:12.0
ARCHS := arm64
include $(THEOS)/makefiles/common.mk
TOOL_NAME = ceserver

ceserver_FILES = ceserver.c api.c debugger.c porthelp.c symbols.c
ceserver_CFLAGS += -fblocks
ceserver_CODESIGN_FLAGS = -Sentitlements.plist
ceserver_LIBRARIES = z

include $(THEOS_MAKE_PATH)/tool.mk
