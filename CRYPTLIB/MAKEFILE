#****************************************************************************
#*																			*
#*						Makefile for the encryption library					*
#*																			*
#****************************************************************************

PROJ	= crypt
LIBNAME	= lib$(PROJ).a

CFLAGS	= -c -D__UNIX__ -O -I. $(CMDC)	# Flags for compiler

LFLAGS	= $(CMDL)			# Flags for linker

OUTPATH	=					# Where object files go (/tmp is a good place)
OBJ		= .o				# Extension for object files

LD		= $(CC)				# Linker (just use the C compiler)
ECHO	= echo				# Echo to screen command
MAKE	= make				# The make command

# The object files which make up the library

OBJS	= $(OUTPATH)crypt$(OBJ) $(OUTPATH)lib_3des$(OBJ) \
		  $(OUTPATH)lib_des$(OBJ) $(OUTPATH)lib_idea$(OBJ) \
		  $(OUTPATH)lib_mdc$(OBJ) $(OUTPATH)lib_null$(OBJ) \
		  $(OUTPATH)lib_rc4$(OBJ) $(OUTPATH)idea$(OBJ) \
		  $(OUTPATH)3ecb_enc$(OBJ) $(OUTPATH)ecb_enc$(OBJ) \
		  $(OUTPATH)pcbc_enc$(OBJ) $(OUTPATH)set_key$(OBJ) \
		  $(OUTPATH)rc4$(OBJ) $(OUTPATH)shs$(OBJ) 

#****************************************************************************
#*																			*
#*			If no args are given, print a usage message and exit			*
#*																			*
#****************************************************************************

default:
		@$(ECHO)
		@$(ECHO) "Usage: make <system-type>"
		@$(ECHO)
		@$(ECHO) "To create the encryption library, you have to enter the Unix system type"
		@$(ECHO) "you want to build it for.  Possible options are: aix, aix370, aix386,"
		@$(ECHO) "bsd386, convex, irix, hpux, hpux-gcc, isc, linux, mint, mipsbsd, next, osf1,"
		@$(ECHO) "qnx, sun, svr4, ultrix, and uts4.  If none of the above fit, try 'make "
		@$(ECHO) "generic', and send a copy of any changes necessary to the author, "
		@$(ECHO) "pgut01@cs.auckland.ac.nz"
		@$(ECHO)
		@$(ECHO) "After the library has been created, use 'make test' to build a test program"
		@$(ECHO) "with it."

love:
		@$(ECHO) "Nicht wahr?"
		@$(ECHO)

#****************************************************************************
#*																			*
#*					Rules to build the encryption library					*
#*																			*
#****************************************************************************

# Main directory

$(OUTPATH)crypt$(OBJ):		crypt.h crypt.c
							$(CC) $(CFLAGS) crypt.c

$(OUTPATH)lib_3des$(OBJ):	crypt.h libdes/des.h lib_3des.c
							$(CC) $(CFLAGS) lib_3des.c

$(OUTPATH)lib_des$(OBJ):	crypt.h testdes.h libdes/des.h lib_des.c
							$(CC) $(CFLAGS) lib_des.c

$(OUTPATH)lib_idea$(OBJ):	crypt.h idea/idea.h testidea.h lib_idea.c
							$(CC) $(CFLAGS) lib_idea.c

$(OUTPATH)lib_mdc$(OBJ):	crypt.h mdc/shs.h lib_mdc.c
							$(CC) $(CFLAGS) lib_mdc.c

$(OUTPATH)lib_null$(OBJ):	crypt.h lib_null.c
							$(CC) $(CFLAGS) lib_null.c

$(OUTPATH)lib_rc4$(OBJ):	crypt.h testrc4.h rc4/rc4.h lib_rc4.c
							$(CC) $(CFLAGS) lib_rc4.c

$(OUTPATH)test$(OBJ):		crypt.h test.c
							$(CC) $(CFLAGS) test.c

# idea subdirectory

$(OUTPATH)idea$(OBJ):		idea/idea.h idea/idea.c
							$(CC) $(CFLAGS) idea/idea.c

# libdes subdirectory

$(OUTPATH)3ecb_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/3ecb_enc.c
							$(CC) $(CFLAGS) libdes/3ecb_enc.c

$(OUTPATH)ecb_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/spr.h \
							libdes/version.h libdes/ecb_enc.c
							$(CC) $(CFLAGS) libdes/ecb_enc.c

$(OUTPATH)pcbc_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/pcbc_enc.c
							$(CC) $(CFLAGS) libdes/pcbc_enc.c

$(OUTPATH)set_key$(OBJ):	libdes/des.h libdes/des_locl.h libdes/podd.h \
							libdes/sk.h libdes/set_key.c
							$(CC) $(CFLAGS) libdes/set_key.c

# rc4 subdirectory

$(OUTPATH)rc4$(OBJ):		rc4/rc4.h rc4/rc4.c
							$(CC) $(CFLAGS) rc4/rc4.c

# mdc subdirectory

$(OUTPATH)shs$(OBJ):		mdc/shs.h mdc/shs.c
							$(CC) $(CFLAGS) mdc/shs.c

# Create the library.  The test program is also listed as a dependancy
# since we need to use OS-specific compiler options for it which a
# simple 'make test' won't give us (yuck).

$(LIBNAME):					$(OBJS) $(OUTPATH)test$(OBJ)
							ar rc $(LIBNAME) $(OBJS)

# Link everything into a test program

test:	$(LIBNAME) $(OUTPATH)test$(OBJ)
		@$(LD) -o testcrypt $(LFLAGS) $(OUTPATH)test$(OBJ) -L. -l$(PROJ)

#****************************************************************************
#*																			*
#*						Defines for each variation of Unix					*
#*																			*
#****************************************************************************

# AIX for the RS6000: Use cc.  Differs from AIX370/386 in endianness

aix:
		@$(MAKE) $(LIBNAME) CC="cc"

# AIX370, AIX386: Use cc

aix370:
		@$(MAKE) $(LIBNAME) CC="cc"
aix386:
		@$(MAKE) $(LIBNAME) CC="cc"

# AUX: The only Unix so bloated it has /etc.etc.etc

# BSD 386: Use cc

bsd386:
		@$(MAKE) $(LIBNAME) CC="cc"

# Convex: Use cc (cc has some bugs)

convex:
		@$(MAKE) $(LIBNAME) CC="cc"

# Esix: Run away!!  Run away!!

# Generic: Generic BSD-ish system running gcc

generic:
		@$(MAKE) $(LIBNAME) CC="gcc"

# HPUX: Use cc if you have the ANSI C compiler, otherwise use gcc
#       Need to use '-Aa -D_HPUX_SOURCE' as compiler options to get
#       C compiler into ANSI C mode with UNIX symbols.

hpux:
		@$(MAKE) $(LIBNAME) CMDC="-Aa -D_HPUX_SOURCE +O3" CC="cc"

hpux-gcc:
		@$(MAKE) $(LIBNAME) CC="gcc"

# Irix: Use cc with the -acpp flag for maximum ANSI-ness

irix:
		@$(MAKE) $(LIBNAME) CMDC="-acpp" CC="cc"

# ISC Unix: Use gcc

isc:
		@$(MAKE) $(LIBNAME) CC="gcc"

# Linux: Use gcc

linux:
		@$(MAKE) $(LIBNAME) CC="gcc"

# MiNT: Use gcc

mint:
		@$(MAKE) $(LIBNAME) CC="gcc"

# Risc/OS 4: Use gcc

mipsbsd:
		@$(MAKE) $(LIBNAME) CC="gcc"

# NeXT 3.0: Use cc

next:
		@$(MAKE) $(LIBNAME) CMDC="-O2" CMDL="-object -s" CC="cc"

# OSF 1: Use gcc

osf1:
		@$(MAKE) $(LIBNAME) CC="gcc"

# QNX 4.x: Use cc -ml, ld -N32768 -ml

qnx:
		@$(MAKE) $(LIBNAME) CMDC="-ml" CMDL="-N32768 -ml" CC="cc"

# Sun/Slowaris: Use gcc

sun:
		@$(MAKE) $(LIBNAME) CC="gcc"

# SVR4: Use cc.  Better results can be obtained by upgrading your OS to
#       4.4 BSD.

svr4:
		@$(MAKE) $(LIBNAME) CC="cc"

# Ultrix: Use vcc or gcc

ultrix:
		@$(MAKE) $(LIBNAME) CC="gcc"

# Amdahl UTS 4: Use cc

uts4:
		@$(MAKE) $(LIBNAME) CMDC="-Xc", CC="cc"

#****************************************************************************
#*																			*
#*						Cleanup after make has finished						*
#*																			*
#****************************************************************************

clean:
		rm -f *.o core testcrypt $(LIBNAME)
