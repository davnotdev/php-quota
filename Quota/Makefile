# Standard Makefile derived from the provided Perl script

# Define OS detection
OS := $(shell uname -rs)
CONFIG :=
EXTRALIBS :=
EXTRAINC :=
PICOBJ :=
HASAFS :=
AFSQUOTA :=
HASVXFS :=
RPCLIBS := -lrpcsvc
EXTRAOBJ :=

# Configuration based on OS
ifeq ($(findstring SunOS 4.1,$(OS)),SunOS 4.1)
    CONFIG := sunos_4_1.h
else ifeq ($(findstring SunOS 5,$(OS)),SunOS 5)
    CONFIG := solaris_2.h
else ifneq (,$(filter HP-UX A.09 HP-UX B.10 HP-UX C.11,$(OS)))
    CONFIG := hpux.h
else ifeq ($(findstring IRIX 5,$(OS)),IRIX 5)
    CONFIG := irix_5.h
else ifeq ($(findstring IRIX 6,$(OS)),IRIX 6)
    CONFIG := irix_6.h
else ifeq ($(findstring OSF1,$(OS)),OSF1)
    CONFIG := dec_osf.h
else ifeq ($(findstring Linux,$(OS)),Linux)
    CONFIG := linux.h
    PICOBJ := linuxapi.o
else ifeq ($(findstring AIX,$(OS)),AIX)
    CONFIG := aix_4_1.h
else ifneq (,$(filter dragonfly Darwin FreeBSD NetBSD OpenBSD,$(OS)))
    CONFIG := bsd.h
endif

# Handle myconfig.h
.PHONY: check_myconfig
check_myconfig:
	@if [ -e myconfig.h ] && \
	   ( [ ! -L myconfig.h ] || [ "`readlink myconfig.h`" != "hints/$(CONFIG)" ] ); then \
	    echo "FATAL: myconfig.h already exists."; \
	    echo "You need to do a \"make clean\" before configuring for a new platform."; \
	    echo "If that doesn't help, remove myconfig.h manually."; \
	    exit 1; \
	fi

myconfig.h: check_myconfig
	ln -sf hints/$(CONFIG) myconfig.h

# AFS support
AFS_DIR := /afs
ifneq ($(wildcard $(AFS_DIR)),)
    AFS := $(shell df $(AFS_DIR) 2>/dev/null)
    ifneq ($(findstring AFS,$(AFS)),)
        HASAFS := -DAFSQUOTA
        AFSHOME := $(if $(wildcard /usr/afsws),/usr/afsws,/usr)
        EXTRAINC := -I$(AFSHOME)/include -I$(AFSHOME)/include/afs
        EXTRALIBS += -L$(AFSHOME)/lib -L$(AFSHOME)/lib/afs -lsys -lrx -lrxkad -llwp
        AFSQUOTA := afsquota.o
    endif
endif

# Veritas FS on Solaris
ifeq ($(findstring SunOS,$(OS)),SunOS)
    ifneq ($(wildcard /usr/include/sys/fs/vx_quota.h),)
        HASVXFS := -DSOLARIS_VXFS
        EXTRAOBJ += vxquotactl.o
        @echo "Configured with the VERITAS File System on Solaris"
    endif
endif

# NetBSD quota library
ifneq (,$(filter NetBSD 5.99.%,$(OS)))
    EXTRALIBS += -lquota
endif

# RPC support
ifneq (,$(findstring Linux,$(OS)))
    ifneq ($(wildcard /usr/include/tirpc),)
        ifeq ($(wildcard /usr/include/rpc/rpc.h),)
            EXTRAINC := -I/usr/include/tirpc
            RPCLIBS := -ltirpc
        else
            @echo "WARNING: /usr/include/rpc/rpc.h missing; RPC compilation may fail."
        endif
    endif
endif

# Compiler and flags
CC := gcc
CFLAGS := -O2 -Wall $(EXTRAINC)
LDFLAGS := $(RPCLIBS) $(EXTRALIBS)
OBJECTS := Quota.o stdio_wrap.o $(AFSQUOTA) $(PICOBJ) $(EXTRAOBJ)

# Targets
.PHONY: all clean
.DEFAULT_GOAL := all

all: myconfig.h libquota.a

libquota.a: $(OBJECTS)
	ar rcs $@ $^

clean:
	rm -f *.o libquota.a myconfig.h

