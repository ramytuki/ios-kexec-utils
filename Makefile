OBJROOT	=	BUILD/obj
DSTROOT	=	BUILD/dst
SYMROOT	=	BUILD/sym
LDID	=	ldid
SFLAGS	=	-Stfp0.plist
SDKROOT	=	/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS6.1.sdk/
CC	=	xcrun -sdk iphoneos clang -arch armv7
CFLAGS	=	-no-integrated-as -DINLINE_IT_ALL
LDFLAGS	=	-miphoneos-version-min=6.0 -framework IOKit -framework CoreFoundation

all:	multi_kloader kloader ibsspatch img3maker

kloader:	kloader.c
	SDKROOT=$(SDKROOT) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(LDID) $(SFLAGS) $@

multi_kloader:	multi_kloader.c
	SDKROOT=$(SDKROOT) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(LDID) $(SFLAGS) $@

ibsspatch:		patch.c util.c ibootsup.c iboot_patcher.c
	SDKROOT=$(SDKROOT) $(CC) $(CFLAGS) -o $@ patch.c util.c ibootsup.c iboot_patcher.c
	$(LDID) $@

img3maker:	img3maker.c
	SDKROOT=$(SDKROOT) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(LDID) $@

clean:
	rm -f kloader ibsspatch img3maker multi_kloader
	rm -rf $(OBJROOT) $(DSTROOT) $(SYMROOT)

install:	all
	mkdir -p $(DSTROOT)/usr/local/bin
	install -c -m 755 multi_kloader $(DSTROOT)/usr/local/bin
	install -c -m 755 kloader $(DSTROOT)/usr/local/bin
	install -c -m 755 ibsspatch $(DSTROOT)/usr/local/bin
	install -c -m 755 img3maker $(DSTROOT)/usr/local/bin
