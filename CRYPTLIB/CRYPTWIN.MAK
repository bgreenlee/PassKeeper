# Microsoft Visual C++ generated build script - Do not modify

PROJ = CRYPTWIN
DEBUG = 0
PROGTYPE = 1
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = C:\WORK\CRYPT\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = CRYPT.C     
FIRSTCPP =             
RC = rc
CFLAGS_D_WDLL = /nologo /G2 /W3 /Zi /ALw /Od /D "_DEBUG" /D "__WINDOWS__" /GD /Fd"CRYPT.PDB"
CFLAGS_R_WDLL = /nologo /G2 /W3 /ALw /O1 /D "NDEBUG" /D "__WINDOWS__" /GD 
LFLAGS_D_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /CO 
LFLAGS_R_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE 
LIBS_D_WDLL = oldnames libw ldllcew 
LIBS_R_WDLL = oldnames libw ldllcew 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = CRYPTWIN.DEF
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WDLL)
LFLAGS = $(LFLAGS_D_WDLL)
LIBS = $(LIBS_D_WDLL)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WDLL)
LFLAGS = $(LFLAGS_R_WDLL)
LIBS = $(LIBS_R_WDLL)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = CRYPT.SBR \
		LIB_3DES.SBR \
		LIB_IDEA.SBR \
		LIB_DES.SBR \
		LIB_MDC.SBR \
		LIB_NULL.SBR \
		LIB_RC4.SBR \
		IDEA.SBR \
		3ECB_ENC.SBR \
		ECB_ENC.SBR \
		PCBC_ENC.SBR \
		SET_KEY.SBR \
		RC4.SBR \
		SHS.SBR


CRYPT_DEP = c:\work\crypt\crypt.h


LIB_3DES_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\libdes/des.h


LIB_IDEA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\idea/idea.h \
	c:\work\crypt\ideatest.h


LIB_DES_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\libdes/des.h \
	c:\work\crypt\destest.h


LIB_MDC_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\mdc/shs.h


LIB_NULL_DEP = c:\work\crypt\crypt.h


LIB_RC4_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\rc4/rc4.h \
	c:\work\crypt\rc4test.h


CRYPTWIN_RCDEP = 

IDEA_DEP = c:\work\crypt\idea\idea.h \
	idea/idea.h


3ECB_ENC_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	libdes/des_locl.h


ECB_ENC_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	c:\work\crypt\libdes\spr.h \
	c:\work\crypt\libdes\version.h \
	libdes/des_locl.h \
	libdes/spr.h \
	libdes/version.h


PCBC_ENC_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	libdes/des_locl.h


SET_KEY_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	c:\work\crypt\libdes\podd.h \
	c:\work\crypt\libdes\sk.h \
	libdes/des_locl.h \
	libdes/podd.h \
	libdes/sk.h


RC4_DEP = c:\work\crypt\rc4\rc4.h \
	rc4/rc4.h


SHS_DEP = c:\work\crypt\mdc\shs.h \
	mdc/shs.h


all:	$(PROJ).DLL

CRYPT.OBJ:	CRYPT.C $(CRYPT_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c CRYPT.C

LIB_3DES.OBJ:	LIB_3DES.C $(LIB_3DES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIB_3DES.C

LIB_IDEA.OBJ:	LIB_IDEA.C $(LIB_IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIB_IDEA.C

LIB_DES.OBJ:	LIB_DES.C $(LIB_DES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIB_DES.C

LIB_MDC.OBJ:	LIB_MDC.C $(LIB_MDC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIB_MDC.C

LIB_NULL.OBJ:	LIB_NULL.C $(LIB_NULL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIB_NULL.C

LIB_RC4.OBJ:	LIB_RC4.C $(LIB_RC4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIB_RC4.C

CRYPTWIN.RES:	CRYPTWIN.RC $(CRYPTWIN_RCDEP)
	$(RC) $(RCFLAGS) $(RCDEFINES) -r CRYPTWIN.RC

IDEA.OBJ:	IDEA\IDEA.C $(IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c IDEA\IDEA.C

3ECB_ENC.OBJ:	LIBDES\3ECB_ENC.C $(3ECB_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIBDES\3ECB_ENC.C

ECB_ENC.OBJ:	LIBDES\ECB_ENC.C $(ECB_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIBDES\ECB_ENC.C

PCBC_ENC.OBJ:	LIBDES\PCBC_ENC.C $(PCBC_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIBDES\PCBC_ENC.C

SET_KEY.OBJ:	LIBDES\SET_KEY.C $(SET_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIBDES\SET_KEY.C

RC4.OBJ:	RC4\RC4.C $(RC4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RC4\RC4.C

SHS.OBJ:	MDC\SHS.C $(SHS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c MDC\SHS.C


$(PROJ).DLL::	CRYPTWIN.RES

$(PROJ).DLL::	CRYPT.OBJ LIB_3DES.OBJ LIB_IDEA.OBJ LIB_DES.OBJ LIB_MDC.OBJ LIB_NULL.OBJ \
	LIB_RC4.OBJ IDEA.OBJ 3ECB_ENC.OBJ ECB_ENC.OBJ PCBC_ENC.OBJ SET_KEY.OBJ RC4.OBJ SHS.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
CRYPT.OBJ +
LIB_3DES.OBJ +
LIB_IDEA.OBJ +
LIB_DES.OBJ +
LIB_MDC.OBJ +
LIB_NULL.OBJ +
LIB_RC4.OBJ +
IDEA.OBJ +
3ECB_ENC.OBJ +
ECB_ENC.OBJ +
PCBC_ENC.OBJ +
SET_KEY.OBJ +
RC4.OBJ +
SHS.OBJ +
$(OBJS_EXT)
$(PROJ).DLL
$(MAPFILE)
c:\msvc\lib\+
c:\windows\system\+
f:\osl_prod\ml-550\win\+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) CRYPTWIN.RES $@
	@copy $(PROJ).CRF MSVC.BND
	implib /nowep $(PROJ).LIB $(PROJ).DLL

$(PROJ).DLL::	CRYPTWIN.RES
	if not exist MSVC.BND 	$(RC) $(RESFLAGS) CRYPTWIN.RES $@

run: $(PROJ).DLL
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
