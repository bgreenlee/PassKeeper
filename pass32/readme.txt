PassKeeper 1.2, 32-bit
by Brad Greenlee
Copyright 1996 Brad Greenlee
All Rights Reserved
http://www.isys.hu/staff/brad/passkeeper.html

Introduction
------------
PassKeeper is a Windows utility that allows you keep a list of accounts with
usernames, passwords, and notes. This list is stored encrypted.

I developed PassKeeper in order to keep track of the many different "accounts"
I have across the Net. Many services on the Web, for example, require you to
register and give out a username and password, which you are often allowed
to pick out yourself, but not always. Examples of such services include
HotWired, Pathfinder, Amazon, etc. Of course, PassKeeper can be used to safely
keep a record of anything, really.

PassKeeper is freeware for individual and non-commercial users. Commercial
users are asked to pay $10 per copy. I also ask that this file remains with
any redistribution of PassKeeper. 

If you find any bugs or have any suggestions on improving PassKeeper, feel 
free to email me at brad@isys.hu

The most up-to-date version of PassKeeper can always be found at
http://www.isys.hu/staff/brad/passkeeper.html

I assume no liability for lost data or any other damages caused directly or
indirectly by this program. If you forget your password or you stumble across 
a bug that prevents you from accessing your password file (there was one 
such bug in version 1.0), please do not ask me to recover your file. I can't. 
Just delete PASS.DAT and start over. 

Please see the copyright info below.

PassKeeper uses Eric Young's implementation of CBC Triple DES Encryption.
Please see his copyright info at the end of this document.


Installation and Usage
----------------------
Installation is simple. You've already done it. Passkeeper doesn't rely on any
files outside of the directory it's in, so you can move it anywhere. When you 
run PASS32.EXE for the first time, you will be asked to enter the password 
you would like to use to access PassKeeper in the future. This password is 
also the key to encrypting and decrypting your data. It is VERY important that 
you do not forget this password; if you do, your data will be lost forever (or
at least until someone figures out how to crack Triple DES in a reasonable amount
of time). You can change your password later, but only after logging in to the 
program.

PassKeeper creates two files:
  PASS.INI  Contains the user-configurable options.
  PASS.DAT  Contains the encrypted data.

If someone else using this machine would like to have their own PassKeeper
list, make another copy of PASS32.EXE in a separate directory.

If you ever forget your password the only thing you can do is delete the
PASS.DAT file. You will lose all your entries of course. Actually, I suggest
just renaming PASS.DAT or storing it somewhere else just in case you
eventually remember the password.

Finally, it's always a good idea to keep a backup copy of PASS.DAT somewhere, 
just in case it gets corrupted or deleted.

Some users have written asking if they can have multiple users sharing one copy
of PassKeeper. Although this feature isn't built in to the program (it's on the
list of enhancements for the next version, though), you can still achieve this
by creating multiple aliases to the program, with each having a different working
directory. In Windows 95, you would create a shortcut to PASS32.EXE, then bring
up the properties of that shortcut, click on the "Shortcut" tab, and in the
"Start in:" field, enter the directory you would like to store the new user's
PASS.DAT file. PassKeeper will look for PASS.DAT in this directory.


Options
-------
PassKeeper has only two user-configurable options:
  Confirm Remove        When this option is checked, you will be asked
                        whether you really want to remove an item when you
                        click the 'Remove' button.

  Auto-Save on Quit     When this option is checked, any changes you made
                        while in PassKeeper will be saved automatically upon
                        Quit (or Exit, or Close). Otherwise, you will be asked
                        whether you would like to save your changes.


Bugs
----
There is one, presently. Avoid using certain characters in the "Account" field and
this won't be a problem. Those characters include |\_ and probably a few more. The
problem is this: the list box you see on the screen, containing all the account 
names, automatically sorts any entries I put in it. Also, the data structure I use
internally to store the list is also automatically sorted. Unfortunately, even
though these both come from the same company (I used Borland's OWL in writing this),
they seem sort those characters differently. Thus, say you have two entries, one
labelled 'my_account' and the other 'myaccount'. On screen, you may see 
'my_account' before 'myaccount', but when you click on 'my_account', the data for
'myaccount' appears. I haven't fixed this yet because the fix is non-trivial, and
I figured it was rare enough and harmless enough (just change the account names if 
you have this problem), that it could wait until I get around to writing the next
version.

As for when the next version will be out...I don't know. There are a *lot* of
features I'd like to add. If you send me an email, though, I'd be happy to add you
to the list of people I will notify when the new version comes out.


Future Enhancements
-------------------
Here are some of the items on my to-do list for PassKeeper:
 o Longer fields (probably up to 255 characters each)
 o Search. I have so many accounts in my PassKeeper that sometimes I forget what
   I used for the account name, and it takes me a bit to scroll through and find it. 
   If I could search for key words, it would make things easier.
 o The ability to put it into the Windows 95 tray.
 o Multi-user support
 o Multi-list support. For example, you may have a list of all the registration
   numbers of software you registered and another for accounts you have on the Web.
 o The ability to define your own forms. Using the example above, your form for
   your list of registration numbers may just have the fields 'Software Title',
   and 'Registration Number', where as the form for a list of accounts on the Web
   may have 'Account Name', 'Username', 'Password', and 'URL'.
 
Any other suggestions? Any and all are welcome. 


Version History
---------------
1.2     96.04.25
        Fixed a nasty bug that caused certain main passwords of less than
        6 characters from working. It's not the same as the bug in 1.01, but
        related.

        You can now only enter account names that begin with an alphanumeric
        character. This is to avoid a strange bug that appears if you enter
        an account name that starts with certain non-alphanumeric characters.
        
        It now checks for duplicate account names when you add or edit an 
        account. You cannot have two identical account names.
    
        Changed some other very minor things.
        
1.11    96.04.23
        You can now use the enter key in the notes field.
        
1.1     96.01.27
        Fixed bug that caused a crash if you tried to remove and item with
        Comfirm Remove on. I figured this was serious enough to bump up the
        minor revision number.

1.01    95.12.04
        Fixed bug that prevented main passwords of less than 6 characters
        from working.

        Username and password are no longer required fields. Only the Account
        field is required.


That's it. Thanks for using PassKeeper!


Brad Greenlee
brad@isys.hu
http://www.isys.hu/staff/brad/

Budapest
24 April 1996


PassKeeper Copyright Info
------------------
Copyright (C) 1996 Brad Greenlee (brad@isys.hu)
All rights reserved.

This program is free for commercial and non-commercial use as long as
the following conditions are aheared to.  

Copyright remains Brad Greenlee's, and as such any Copyright notices in
the program are not to be removed.

THIS SOFTWARE IS PROVIDED BY BRAD GREENLEE ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.



DES Copyright Info
------------------
Copyright (C) 1995 Eric Young (eay@mincom.oz.au)
All rights reserved.

This package is an DES implementation written by Eric Young (eay@mincom.oz.au).
The implementation was written so as to conform with MIT's libdes.

This library is free for commercial and non-commercial use as long as
the following conditions are aheared to.  The following conditions
apply to all code found in this distribution.

Copyright remains Eric Young's, and as such any Copyright notices in
the code are not to be removed.
If this package is used in a product, Eric Young should be given attribution
as the author of that the SSL library.  This can be in the form of a textual
message at program startup or in documentation (online or textual) provided
with the package.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by Eric Young (eay@mincom.oz.au)

THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

The license and distribution terms for any publically available version or
derivative of this code cannot be changed.  i.e. this code cannot simply be
copied and put under another distrubution license
[including the GNU Public License.]

The reason behind this being stated in this direct manner is past
experience in code simply being copied and the attribution removed
from it and then being distributed as part of other packages. This
implementation was a non-trivial and unpaid effort.
