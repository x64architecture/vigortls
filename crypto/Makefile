#
# OpenSSL/crypto/Makefile
#

DIR=		crypto
TOP=		..
CC=		cc
INCLUDE=	-I. -I$(TOP) -I../include $(ZLIB_INCLUDE)
# INCLUDES targets sudbirs!
INCLUDES=	-I.. -I../.. -I../modes -I../asn1 -I../evp -I../../include $(ZLIB_INCLUDE)
CFLAG=		-g
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=       Makefile
RM=             rm -f
AR=		ar r

RECURSIVE_MAKE=	[ -n "$(SDIRS)" ] && for i in $(SDIRS) ; do \
		    (cd $$i && echo "making $$target in $(DIR)/$$i..." && \
		    $(MAKE) -e TOP=../.. DIR=$$i INCLUDES='$(INCLUDES)' $$target ) || exit 1; \
		done;

PEX_LIBS=
EX_LIBS=
 
CFLAGS= $(INCLUDE) $(CFLAG)
ASFLAGS= $(INCLUDE) $(ASFLAG)
AFLAGS=$(ASFLAGS)
CPUID_OBJ=mem_clr.o

LIBS=

GENERAL=Makefile README crypto-lib.com install.com

LIB= $(TOP)/libcrypto.a
SHARED_LIB= libcrypto$(SHLIB_EXT)
LIBSRC=	cryptlib.c malloc_wrapper.c mem_clr.c mem_dbg.c ex_data.c cpt_err.c \
	uid.c time_support.c o_str.c directory.c o_init.c
LIBOBJ= cryptlib.o malloc_wrapper.o mem_dbg.o ex_data.o cpt_err.o \
	uid.o time_support.o o_str.o directory.o o_init.o $(CPUID_OBJ)

SRC= $(LIBSRC)

EXHEADER= crypto.h opensslv.h opensslconf.h \
	ossl_typ.h
HEADER=	cryptlib.h md32_common.h time_support.h o_str.h directory.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all: shared

x86cpuid.s:	x86cpuid.pl perlasm/x86asm.pl
	$(PERL) x86cpuid.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

x86_64cpuid.s: x86_64cpuid.pl;	$(PERL) x86_64cpuid.pl $(PERLASM_SCHEME) > $@
ia64cpuid.s: ia64cpuid.S;	$(CC) $(CFLAGS) -E ia64cpuid.S > $@
ppccpuid.s:	ppccpuid.pl;	$(PERL) ppccpuid.pl $(PERLASM_SCHEME) $@
pariscid.s:	pariscid.pl;	$(PERL) pariscid.pl $(PERLASM_SCHEME) $@

testapps:
	[ -z "$(THIS)" ] || (	if echo $(SDIRS) | fgrep ' des '; \
				then cd des && $(MAKE) -e des; fi )
	[ -z "$(THIS)" ] || ( cd pkcs7 && $(MAKE) -e testapps );
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

subdirs:
	@target=all; $(RECURSIVE_MAKE)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO
	@target=files; $(RECURSIVE_MAKE)

links:
	@$(PERL) $(TOP)/util/mklink.pl ../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../apps $(APPS)
	@target=links; $(RECURSIVE_MAKE)

# lib: $(LIB): are splitted to avoid end-less loop
lib:	$(LIB)
	@touch lib
$(LIB):	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.

shared: lib subdirs
	if [ -n "$(SHARED_LIBS)" ]; then \
		(cd ..; $(MAKE) $(SHARED_LIB)); \
	fi

libs:
	@target=lib; $(RECURSIVE_MAKE)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ;\
	do \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;
	@target=install; $(RECURSIVE_MAKE)

lint:
	@target=lint; $(RECURSIVE_MAKE)

depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDE) $(DEPFLAG) -- $(PROGS) $(LIBSRC)
	@[ -z "$(THIS)" ] || (set -e; target=depend; $(RECURSIVE_MAKE) )
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

clean:
	rm -f *.s *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
	@target=clean; $(RECURSIVE_MAKE)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f opensslconf.h
	@target=dclean; $(RECURSIVE_MAKE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

cpt_err.o: ../include/openssl/bio.h ../include/openssl/crypto.h
cpt_err.o: ../include/openssl/e_os2.h ../include/openssl/err.h
cpt_err.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
cpt_err.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
cpt_err.o: ../include/openssl/safestack.h ../include/openssl/stack.h
cpt_err.o: cpt_err.c
cryptlib.o: ../include/openssl/bio.h ../include/openssl/buffer.h
cryptlib.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
cryptlib.o: ../include/openssl/err.h ../include/openssl/lhash.h
cryptlib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cryptlib.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
cryptlib.o: ../include/openssl/stack.h cryptlib.c
cryptlib.o: cryptlib.h
ex_data.o: ../include/openssl/bio.h ../include/openssl/buffer.h
ex_data.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ex_data.o: ../include/openssl/err.h ../include/openssl/lhash.h
ex_data.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ex_data.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
ex_data.o: ../include/openssl/stack.h cryptlib.h
ex_data.o: ex_data.c
malloc_wrapper.o: ../include/openssl/bio.h ../include/openssl/buffer.h
malloc_wrapper.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
malloc_wrapper.o: ../include/openssl/err.h ../include/openssl/lhash.h
malloc_wrapper.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
malloc_wrapper.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
malloc_wrapper.o: ../include/openssl/stack.h cryptlib.h
malloc_wrapper.o: malloc_wrapper.c
mem_clr.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
mem_clr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mem_clr.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
mem_clr.o: ../include/openssl/stack.h mem_clr.c
mem_dbg.o: ../include/openssl/bio.h ../include/openssl/buffer.h
mem_dbg.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
mem_dbg.o: ../include/openssl/err.h ../include/openssl/lhash.h
mem_dbg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mem_dbg.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
mem_dbg.o: ../include/openssl/stack.h cryptlib.h
mem_dbg.o: mem_dbg.c
directory.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
directory.o: directory.c directory.h
o_init.o: ../include/openssl/bio.h ../include/openssl/crypto.h
o_init.o: ../include/openssl/e_os2.h ../include/openssl/err.h
o_init.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
o_init.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
o_init.o: ../include/openssl/safestack.h ../include/openssl/stack.h
o_init.o: o_init.c
o_str.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
o_str.o: o_str.c o_str.h
time_support.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h time_support.c
time_support.o: time_support.h
uid.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
uid.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
uid.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
uid.o: ../include/openssl/stack.h uid.c
