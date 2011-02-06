' A warning to parents that this programming language is unsuited for small
' children

Option Explicit

'****************************************************************************
'*                                                                          *
'*                      Encryption Algorithm Types/Modes                    *
'*                                                                          *
'****************************************************************************

' The encryption algorithms we can use

Global Const CRYPT_ALGO_NONE = 0            ' No encryption
Global Const CRYPT_ALGO_MDCSHS = 1          ' MDC/SHS
Global Const CRYPT_ALGO_DES = 2             ' DES
Global Const CRYPT_ALGO_3DES = 3            ' Two-key triple DES
Global Const CRYPT_ALGO_IDEA = 4            ' IDEA
Global Const CRYPT_ALGO_RC4 = 4             ' RC4
Global Const CRYPT_ALGO_LAST = 4            ' Last possible crypt algo value

' The encryption modes we can use

Global Const CRYPT_MODE_NONE = 0            ' No encryption
Global Const CRYPT_MODE_STREAM = 1          ' Stream cipher
Global Const CRYPT_MODE_ECB = 2             ' ECB
Global Const CRYPT_MODE_CBC = 3             ' CBC
Global Const CRYPT_MODE_CFB = 4             ' CFB
Global Const CRYPT_MODE_OFB = 5             ' OFB
Global Const CRYPT_MODE_PCBC = 6            ' PCBC
Global Const CRYPT_MODE_LAST = 6            ' Last possible crypt algo value

'****************************************************************************
'*                                                                          *
'*                  Library-Wide Constants and Definitions                  *
'*                                                                          *
'****************************************************************************

' The maximum user key size - 2048 bits

Global Const CRYPT_MAX_KEYSIZE = 256

' The maximum IV size - 256 bits

Global Const CRYPT_MAX_IVSIZE = 64

' The maximum speed ratio for an encryption algorithm

Global Const CRYPT_MAX_SPEED = 1000

'****************************************************************************
'*                                                                          *
'*                              Data Structures                             *
'*                                                                          *
'****************************************************************************

' An encryption context.  Note the order of the BYTE[] fields in this
' structure, which ensures they're aligned to the machine word size

Type CRYPT_INFO
    ' Basic information on the encryption we're using (a pointer to an
    ' internal data structure)
    capabilityInfo As Long          ' The encryption capability data

    ' User keying information.  The user key is the key as entered by the
    ' user, the transformed user key is (for those algoriths which do this)
    ' the user key transformed by whatever key preprocessing method is used,
    ' stored in canonical form.  The IV is the initial IV stored in canonical
    ' form
    userKey As String * MAX_KEYSIZE ' User encryption key
    transUserKey As String * MAX_KEYSIZE    ' Transformed user key
    iv As String * MAX_IVSIZE       ' Initial IV
    userKeyLength As Integer        ' User encryption key length in bytes
    ivLength As Integer             ' IV length in bytes
    keySet As Integer               ' Whether the key is set up
    ivSet As Integer                ' Whether the IV is set up

    ' Keying information.  The key is the raw encryption key stored in
    ' whatever form is required by the algorithm.  This may be simply an
    ' endianness-adjusted form of the transformed key (in the case of
    ' algorithms like MDC/SHS) or a processed form of the user key (in the
    ' case of algorithms like DES or IDEA).  The IV is the current working
    ' IV stored in an endianness-adjusted form.  The ivCount is the number
    ' of bytes of IV in use, and may be used for various chaining modes.
    ' These fields may be unused if the algorithm is implemented in hardware
    key As Long                     ' Pointer to internal working key
    currentIV As String * MAX_IVSIZE    ' Internal working IV
    keyLength As Integer            ' Internal key length in bytes
    ivCount As Integer              ' Internal IV count for chaining modes

    ' Private data needed by the algorithm
    privateData As Long             ' For private use
End Type

' Extra algorithm-specific information stored within a crypt context

Type CRYPT_INFO_MDCSHS
    keySetupIterations As Integer   ' No.iterations for user key setup
End Type

' Results returned from the encryption capability query

Type CRYPT_QUERY_INFO
    ' The algorithm, encryption mode, and algorithm name.  Note that the
    ' algorithm name is a pointer to a C string, which current versions of
    ' Visual Basic can't handle when they're inside a structure.  To use it,
    ' you need to extract it into a String in the VB program
    cryptAlgo As Integer            ' The encryption algorithm
    cryptMode As Integer            ' The encryption mode
    algoName As Long                ' The algorithm name

    ' The algorithm parameters
    blockSize As Integer            ' The basic block size of the algorithm
    minKeySize As Integer           ' Minimum key size in bytes
    keySize As Integer              ' Recommended key size in bytes
    maxKeySize As Integer           ' Maximum key size in bytes
    minIVsize As Integer            ' Minimum IV size in bytes
    ivSize As Integer               ' Recommended IV size in bytes
    maxIVsize As Integer            ' Maximum IV size in bytes

    ' Various algorithm characteristics
    speed As Integer                ' Speed relative to block copy
End Type

'****************************************************************************
'*                                                                          *
'*                              Status Codes                                *
'*                                                                          *
'****************************************************************************

' No error in function call

Global Const CRYPT_OK = 0           ' No error

' Generic internal error

Global Const CRYPT_ERROR = -1       ' Nonspecific error

' Failed self-test in encryption code

Global Const CRYPT_SELFTEST = -2    ' Failed self-test

' Error in parameters passed to function

Global Const CRYPT_BADPARM = -3     ' Generic bad argument to function
Global Const CRYPT_BADPARM1 = -4    ' Bad argument, parameter 1
Global Const CRYPT_BADPARM2 = -5    ' Bad argument, parameter 2
Global Const CRYPT_BADPARM3 = -6    ' Bad argument, parameter 3
Global Const CRYPT_BADPARM4 = -7    ' Bad argument, parameter 4
Global Const CRYPT_BADPARM5 = -8    ' Bad argument, parameter 5
Global Const CRYPT_BADPARM6 = -9    ' Bad argument, parameter 6
Global Const CRYPT_BADPARM7 = -10   ' Bad argument, parameter 7
Global Const CRYPT_BADPARM8 = -11   ' Bad argument, parameter 8
Global Const CRYPT_BADPARM9 = -12   ' Bad argument, parameter 9
Global Const CRYPT_BADPARM10 = -13  ' Bad argument, parameter 10
Global Const CRYPT_BADPARM11 = -14  ' Bad argument, parameter 11
Global Const CRYPT_BADPARM12 = -15  ' Bad argument, parameter 12
Global Const CRYPT_BADPARM13 = -16  ' Bad argument, parameter 13
Global Const CRYPT_BADPARM14 = -17  ' Bad argument, parameter 14
Global Const CRYPT_BADPARM15 = -18  ' Bad argument, parameter 15

' Errors due to insufficient resources

Global Const CRYPT_NOMEM = -19      ' Out of memory
Global Const CRYPT_NOTINITED = -20  ' Data has not been initialised
Global Const CRYPT_INITED = -21     ' Data has already been initialised
Global Const CRYPT_NOALGO = -22     ' Algorithm unavailable
Global Const CRYPT_NOMODE = -23     ' Encryption mode unavailable
Global Const CRYPT_NOKEY = -24      ' Key not initialised
Global Const CRYPT_NOIV = -25       ' IV not initialised

'****************************************************************************
'*                                                                          *
'*                              Public Functions                            *
'*                                                                          *
'****************************************************************************

' Initialise and shut down the encryption library

Declare Function initLibrary Lib "Crypt.Dll" () As Integer
Declare Function endLibrary Lib "Crypt.Dll" () As Integer

' Query the capabilities of the encryption library

Declare Function queryModeAvailability Lib "Crypt.Dll" (ByVal cryptAlgo As Integer, ByVal cryptMode As Integer) As Integer
Declare Function queryAlgoAvailability Lib "Crypt.Dll" (ByVal cryptAlgo As Integer) As Integer
Declare Function queryAlgoModeInformation Lib "Crypt.Dll" (ByVal cryptAlgo As Integer, ByVal cryptMode As Integer, cryptQueryInfo As CRYPT_QUERY_INFO) As Integer
Declare Function queryContextInformation Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, cryptQueryInfo As CRYPT_QUERY_INFO) As Integer

' Initialise and destroy an encryption context

Declare Function initCryptContext Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal cryptAlgo As Integer, ByVal cryptMode As Integer) As Integer
Declare Function initCryptContextEx Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal cryptAlgo As Integer, ByVal cryptMode As Integer, cryptInfoEx As Any) As Integer
Declare Function destroyCryptContext Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO) As Integer

' Load a user key into a crypt context

Declare Function loadCryptContext Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal key As String, ByVal keyLength As Integer) As Integer

' Load/retreive an IV into/from a crypt context

Declare Function loadIV Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal iv As String, ByVal length As Integer) As Integer
Declare Function retrieveIV Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal iv As String) As Integer

' Encrypt/decrypt a block of memory

Declare Function encryptBuffer Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal buffer As String, ByVal length As Integer) As Integer
Declare Function decryptBuffer Lib "Crypt.Dll" (cryptInfo As CRYPT_INFO, ByVal buffer As String, ByVal length As Integer) As Integer
