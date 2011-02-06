# Microsoft Visual C++ Generated NMAKE File, Format Version 2.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=Win32 Debug
!MESSAGE No configuration specified.  Defaulting to Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Win32 Release" && "$(CFG)" != "Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "cryptnt.mak" CFG="Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

################################################################################
# Begin Project
MTL=MkTypLib.exe
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "WinRel"
# PROP BASE Intermediate_Dir "WinRel"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "WinRel"
# PROP Intermediate_Dir "WinRel"
OUTDIR=.\WinRel
INTDIR=.\WinRel

ALL : .\cryptnt.dll .\WinRel\cryptnt.bsc

$(OUTDIR) : 
    if not exist $(OUTDIR)/nul mkdir $(OUTDIR)

# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE CPP /nologo /MT /W3 /GX /YX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FR /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "__WINDOWS__" /c
# SUBTRACT CPP /YX /Fr
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "__WINDOWS__" /Fo$(INTDIR)/ /c 
CPP_OBJS=.\WinRel/
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo$(INTDIR)/"CRYPTNT.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_SBRS= \
	
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o$(OUTDIR)/"cryptnt.bsc" 

.\WinRel\cryptnt.bsc : $(OUTDIR)  $(BSC32_SBRS)
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /NOLOGO /SUBSYSTEM:windows /DLL /MACHINE:I386
# ADD LINK32 kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib /NOLOGO /SUBSYSTEM:windows /DLL /PDB:none /MACHINE:I386 /OUT:"cryptnt.dll"
LINK32_FLAGS=kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib\
 shell32.lib /NOLOGO /SUBSYSTEM:windows /DLL /PDB:none /MACHINE:I386\
 /DEF:".\CRYPTNT.DEF" /OUT:"cryptnt.dll" /IMPLIB:$(OUTDIR)/"cryptnt.lib" 
DEF_FILE=.\CRYPTNT.DEF
LINK32_OBJS= \
	.\WinRel\SHS.OBJ \
	.\WinRel\LIB_IDEA.OBJ \
	.\WinRel\SET_KEY.OBJ \
	.\WinRel\CRYPTNT.res \
	.\WinRel\3ECB_ENC.OBJ \
	.\WinRel\IDEA.OBJ \
	.\WinRel\CRYPT.OBJ \
	.\WinRel\LIB_MDC.OBJ \
	.\WinRel\LIB_RC4.OBJ \
	.\WinRel\LIB_3DES.OBJ \
	.\WinRel\LIB_NULL.OBJ \
	.\WinRel\LIB_DES.OBJ \
	.\WinRel\RC4.OBJ \
	.\WinRel\ECB_ENC.OBJ \
	.\WinRel\PCBC_ENC.OBJ

.\cryptnt.dll : $(OUTDIR)  $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "WinDebug"
# PROP BASE Intermediate_Dir "WinDebug"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "WinDebug"
# PROP Intermediate_Dir "WinDebug"
OUTDIR=.\WinDebug
INTDIR=.\WinDebug

ALL : .\cryptnt.dll .\WinDebug\cryptnt.bsc

$(OUTDIR) : 
    if not exist $(OUTDIR)/nul mkdir $(OUTDIR)

# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE CPP /nologo /MT /W3 /GX /Zi /YX /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /c
# ADD CPP /nologo /MT /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "__WINDOWS__" /c
# SUBTRACT CPP /YX /Fr
CPP_PROJ=/nologo /MT /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "__WINDOWS__" /Fo$(INTDIR)/ /Fd$(OUTDIR)/"cryptnt.pdb" /c 
CPP_OBJS=.\WinDebug/
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo$(INTDIR)/"CRYPTNT.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_SBRS= \
	
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o$(OUTDIR)/"cryptnt.bsc" 

.\WinDebug\cryptnt.bsc : $(OUTDIR)  $(BSC32_SBRS)
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /NOLOGO /SUBSYSTEM:windows /DLL /DEBUG /MACHINE:I386
# ADD LINK32 kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib /NOLOGO /SUBSYSTEM:windows /DLL /PDB:none /DEBUG /MACHINE:I386 /OUT:"cryptnt.dll"
LINK32_FLAGS=kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib\
 shell32.lib /NOLOGO /SUBSYSTEM:windows /DLL /PDB:none /DEBUG /MACHINE:I386\
 /DEF:".\CRYPTNT.DEF" /OUT:"cryptnt.dll" /IMPLIB:$(OUTDIR)/"cryptnt.lib" 
DEF_FILE=.\CRYPTNT.DEF
LINK32_OBJS= \
	.\WinDebug\SHS.OBJ \
	.\WinDebug\LIB_IDEA.OBJ \
	.\WinDebug\SET_KEY.OBJ \
	.\WinDebug\CRYPTNT.res \
	.\WinDebug\3ECB_ENC.OBJ \
	.\WinDebug\IDEA.OBJ \
	.\WinDebug\CRYPT.OBJ \
	.\WinDebug\LIB_MDC.OBJ \
	.\WinDebug\LIB_RC4.OBJ \
	.\WinDebug\LIB_3DES.OBJ \
	.\WinDebug\LIB_NULL.OBJ \
	.\WinDebug\LIB_DES.OBJ \
	.\WinDebug\RC4.OBJ \
	.\WinDebug\ECB_ENC.OBJ \
	.\WinDebug\PCBC_ENC.OBJ

.\cryptnt.dll : $(OUTDIR)  $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Group "Source Files"

################################################################################
# Begin Source File

SOURCE=.\MDC\SHS.C
DEP_SHS_C=\
	.\crypt.h\
	.\mdc\shs.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\SHS.OBJ :  $(SOURCE)  $(DEP_SHS_C) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\SHS.OBJ :  $(SOURCE)  $(DEP_SHS_C) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_IDEA.C
DEP_LIB_I=\
	.\crypt.h\
	.\IDEA\idea.h\
	.\ideatest.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\LIB_IDEA.OBJ :  $(SOURCE)  $(DEP_LIB_I) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\LIB_IDEA.OBJ :  $(SOURCE)  $(DEP_LIB_I) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\SET_KEY.C
DEP_SET_K=\
	.\LIBDES\des_locl.h\
	.\LIBDES\podd.h\
	.\LIBDES\sk.h\
	.\LIBDES\des.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\SET_KEY.OBJ :  $(SOURCE)  $(DEP_SET_K) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\SET_KEY.OBJ :  $(SOURCE)  $(DEP_SET_K) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPTNT.RC

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\CRYPTNT.res :  $(SOURCE)  $(INTDIR)
   $(RSC) $(RSC_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\CRYPTNT.res :  $(SOURCE)  $(INTDIR)
   $(RSC) $(RSC_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPTNT.DEF
# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\3ECB_ENC.C
DEP_3ECB_=\
	.\LIBDES\des_locl.h\
	.\LIBDES\des.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\3ECB_ENC.OBJ :  $(SOURCE)  $(DEP_3ECB_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\3ECB_ENC.OBJ :  $(SOURCE)  $(DEP_3ECB_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\IDEA\IDEA.C
DEP_IDEA_=\
	.\IDEA\idea.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\IDEA.OBJ :  $(SOURCE)  $(DEP_IDEA_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\IDEA.OBJ :  $(SOURCE)  $(DEP_IDEA_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPT.C
DEP_CRYPT=\
	.\crypt.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\CRYPT.OBJ :  $(SOURCE)  $(DEP_CRYPT) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\CRYPT.OBJ :  $(SOURCE)  $(DEP_CRYPT) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_MDC.C
DEP_LIB_M=\
	.\crypt.h\
	.\mdc\shs.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\LIB_MDC.OBJ :  $(SOURCE)  $(DEP_LIB_M) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\LIB_MDC.OBJ :  $(SOURCE)  $(DEP_LIB_M) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_RC4.C
DEP_LIB_R=\
	.\crypt.h\
	.\RC4\rc4.h\
	.\rc4test.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\LIB_RC4.OBJ :  $(SOURCE)  $(DEP_LIB_R) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\LIB_RC4.OBJ :  $(SOURCE)  $(DEP_LIB_R) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_3DES.C
DEP_LIB_3=\
	.\crypt.h\
	.\LIBDES\des.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\LIB_3DES.OBJ :  $(SOURCE)  $(DEP_LIB_3) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\LIB_3DES.OBJ :  $(SOURCE)  $(DEP_LIB_3) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_NULL.C
DEP_LIB_N=\
	.\crypt.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\LIB_NULL.OBJ :  $(SOURCE)  $(DEP_LIB_N) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\LIB_NULL.OBJ :  $(SOURCE)  $(DEP_LIB_N) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_DES.C
DEP_LIB_D=\
	.\crypt.h\
	.\LIBDES\des.h\
	.\destest.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\LIB_DES.OBJ :  $(SOURCE)  $(DEP_LIB_D) $(INTDIR)

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\LIB_DES.OBJ :  $(SOURCE)  $(DEP_LIB_D) $(INTDIR)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\RC4\RC4.C
DEP_RC4_C=\
	.\RC4\rc4.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\RC4.OBJ :  $(SOURCE)  $(DEP_RC4_C) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\RC4.OBJ :  $(SOURCE)  $(DEP_RC4_C) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\ECB_ENC.C
DEP_ECB_E=\
	.\LIBDES\des_locl.h\
	.\LIBDES\spr.h\
	.\LIBDES\version.h\
	.\LIBDES\des.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\ECB_ENC.OBJ :  $(SOURCE)  $(DEP_ECB_E) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\ECB_ENC.OBJ :  $(SOURCE)  $(DEP_ECB_E) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\PCBC_ENC.C
DEP_PCBC_=\
	.\LIBDES\des_locl.h\
	.\LIBDES\des.h

!IF  "$(CFG)" == "Win32 Release"

.\WinRel\PCBC_ENC.OBJ :  $(SOURCE)  $(DEP_PCBC_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ELSEIF  "$(CFG)" == "Win32 Debug"

.\WinDebug\PCBC_ENC.OBJ :  $(SOURCE)  $(DEP_PCBC_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

!ENDIF 

# End Source File
# End Group
# End Project
################################################################################
