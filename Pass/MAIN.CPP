#include <owl/owlpch.h>
#include <owl/applicat.h>
#include <owl/framewin.h>
#include "pass.rh"
#include "pass.hpp"
#include "addedit.hpp"
#include "main.hpp"
#include "passdlg.hpp"
#include "passcrpt.hpp"

// globals

bool gModified = false;

/*
class TPassListBox : public TListBox {
	public:
		TPassListBox(TWindow *,int resId);
		LRESULT EvCompareItem(uint ctrlId, COMPAREITEMSTRUCT far& compareInfo);
		void EvDrawItem(uint ctrlId, DRAWITEMSTRUCT far& drawInfo);

	DECLARE_RESPONSE_TABLE(TPassListBox);
};

DEFINE_RESPONSE_TABLE1(TPassListBox, TListBox)
	EV_WM_COMPAREITEM,
	EV_WM_DRAWITEM,
END_RESPONSE_TABLE;

TPassListBox::TPassListBox(TWindow *parent,int resID):TListBox(parent,resID) {}

LRESULT
TPassListBox::EvCompareItem(uint ctrlId, COMPAREITEMSTRUCT far& compareInfo)
{
	char str1[256],str2[256];

	GetString(str1,compareInfo.itemID1);
	GetString(str2,compareInfo.itemID2);

	return stricmp(str1,str2);
}

void
TPassListBox::EvDrawItem(uint ctrlId, DRAWITEMSTRUCT far& drawInfo)
{
	TListBox::EvDrawItem(ctrlId,drawInfo);
}

*/

class TPassListEntry {

	char account[MAX_ENTRY_SIZE],
			 username[MAX_ENTRY_SIZE],
			 password[MAX_ENTRY_SIZE],
			 notes[MAX_NOTES_SIZE];

	public:
		TPassListEntry() {
			strcpy(account,"");
			strcpy(username,"");
			strcpy(password,"");
			strcpy(notes,"");
		}
		TPassListEntry(char* a, char* u, char* p, char* n) {
			strcpy(account,a);
			strcpy(username,u);
			strcpy(password,p);
			strcpy(notes,n);
		}

		char* Account() {return account;}
		char* Username() {return username;}
		char* Password() {return password;}
		char* Notes() {return notes;}

		void Account(char *a) {strcpy(account,a);}
		void Username(char *u) {strcpy(username,u);}
		void Password(char *p) {strcpy(password,p);}
		void Notes(char *n) {strcpy(notes,n);}

		int operator==(const TPassListEntry& e) const {
			return stricmp(account, e.account) ? 0 : 1;
		}

		int operator<(const TPassListEntry& e) const {
			return stricmp(account, e.account) < 0 ? 1 : 0;
		}
};

typedef TSArray<TPassListEntry> TPassList;

TPassList theList(MAX_ENTRIES,0,10);

DEFINE_RESPONSE_TABLE1(TMainWindow, TDialog)
	EV_COMMAND(CM_FILEEXIT, EvQuitButton),
	EV_COMMAND(CM_OPTIONSCONFIRM, EvOptionsConfirm),
	EV_COMMAND(CM_OPTIONSAUTOSAVE, EvOptionsAutoSave),
  EV_COMMAND(CM_OPTIONSPASSWORD, EvOptionsPassword),
	EV_COMMAND(CM_HELPABOUT, EvHelpAbout),
	EV_COMMAND(IDB_ADD,EvAddButton),
	EV_COMMAND(IDB_REMOVE,EvRemoveButton),
	EV_COMMAND(IDB_EDIT,EvEditButton),
	EV_COMMAND(IDB_QUIT,EvQuitButton),
	EV_COMMAND(IDOK,EvEditButton), // allows you to hit return in the listbox to edit
	EV_CHILD_NOTIFY_ALL_CODES(IDC_LISTBOX,EvNotifyListBox),
END_RESPONSE_TABLE;

TMainWindow::TMainWindow():TDialog(0,"DIALOG_MAIN")
{
	listbox = new TListBox(this,IDC_LISTBOX);
	removeButton = new TButton(this, IDB_REMOVE);
	editButton = new TButton(this, IDB_EDIT);
	addButton = new TButton(this, IDB_ADD);

  listbox->SetFocus();
}

TMainWindow::~TMainWindow() {
	delete listbox;
	delete removeButton;
  delete editButton;
	delete addButton;
}

void
TMainWindow::SetupWindow()
{
	TDialog::SetupWindow();

	// do this here so we don't have to make class variables for
	// confirmRemove and autoSave
	char temp[80];
	const char iniPath[] = ".\\pass.ini";

	// check for ini file and create it if it doesn't exist
	ifstream inifile;
	inifile.open(iniPath,ios::nocreate);
	inifile.close();
	if (inifile.fail()) {
		ofstream oinifile;
		oinifile.open(iniPath);
		oinifile << "[settings]\n";
		oinifile << "confirmRemove=1\n";
		oinifile << "autoSave=0\n";
		oinifile.close();
	}

	// Load settings

	GetPrivateProfileString("settings","confirmRemove","1",temp,sizeof(temp),iniPath);
	bool confirmRemove = (atoi(temp) == 1 ? 1 : 0);
	GetPrivateProfileString("settings","autoSave","0",temp,sizeof(temp),iniPath);
	bool autoSave = (atoi(temp) == 1 ? 1 : 0);

	TMenu *theMenu = new TMenu(GetApplication()->GetMainWindow()->GetMenu());

	theMenu->CheckMenuItem(CM_OPTIONSCONFIRM, confirmRemove ?
		MF_CHECKED : MF_UNCHECKED);

	theMenu->CheckMenuItem(CM_OPTIONSAUTOSAVE, autoSave ?
		MF_CHECKED : MF_UNCHECKED);

	delete theMenu;

	LoadData();

	UpdateListBox();
	listbox->SetSelIndex(0);
}

void
TMainWindow::SetMainPassword(char *password) {
	strcpy(mainPassword,password);
}

bool
TMainWindow::Duplicate(char *name) {
	int num = theList.GetItemsInContainer();
	for (int i=0;i < num ;i++)
		if (strcmp(name,theList[i].Account()) == 0) return true;

	return false;
}

void
TMainWindow::LoadData()
{
	// open data file
	ifstream datafile("pass.dat",ios::binary);

	if (!datafile) return;

	TEntry entry;
	TPassListEntry passListEntry;

	int data_size = MAX_CRYPT_SIZE+IV_SIZE;
	unsigned char *data;
	try {
		data = new unsigned char[data_size];
	}
	catch(xalloc) {
		MessageBox("Out of memory at LoadData(1)");
		exit(-1);
	}

	datafile.seekg(MAX_CRYPT_SIZE+IV_SIZE); // skip password

	while (!datafile.eof()) {
		datafile.read(data,data_size);
		if (datafile.gcount() < data_size) {
			datafile.close();
			return;
		}

		//decrypt password
		TCrypt *crypt = new TCrypt();
		crypt->decrypt(data,data_size,(BYTE *)mainPassword);
		delete crypt;

		memcpy(&entry,data,sizeof(entry));

		passListEntry.Account(entry.account);
		passListEntry.Username(entry.username);
		passListEntry.Password(entry.password);
		passListEntry.Notes(entry.notes);

		theList.Add(passListEntry);
	}
	datafile.close();
	delete[] data;
}

void
TMainWindow::SaveData()
{
	unsigned char *buffer;
	try {
		buffer = new unsigned char[MAX_CRYPT_SIZE+IV_SIZE];
	}
	catch(xalloc) {
		MessageBox("Out of memory at SaveData(2)");
		exit(-1);
	}
	memset(buffer,0,sizeof(buffer));
	memcpy(buffer,mainPassword,sizeof(mainPassword));

	TCrypt *crypt = new TCrypt();
	crypt->encrypt(buffer,MAX_CRYPT_SIZE+IV_SIZE,(BYTE *)mainPassword);
	delete crypt;

	ofstream datafile("pass.dat",ios::binary);
	datafile.write(buffer,MAX_CRYPT_SIZE+IV_SIZE);

	TEntry entry;
	int num = theList.GetItemsInContainer();
	for (int i=0;i < num ;i++)
	{
		//encrypt data before we save it
		strcpy(entry.account,theList[i].Account());
		strcpy(entry.username,theList[i].Username());
		strcpy(entry.password,theList[i].Password());
		strcpy(entry.notes,theList[i].Notes());

		memset(buffer,0,MAX_CRYPT_SIZE+IV_SIZE);
		memcpy(buffer,&entry,sizeof(entry));

		TCrypt *crypt = new TCrypt();
		crypt->encrypt(buffer,MAX_CRYPT_SIZE+IV_SIZE,(BYTE *)mainPassword);
		delete crypt;

		datafile.write(buffer,MAX_CRYPT_SIZE+IV_SIZE);
	}
	datafile.close();
	delete[] buffer;

	// Save settings
	TMenu *theMenu = new TMenu(GetApplication()->GetMainWindow()->GetMenu());

	const char iniPath[] = ".\\pass.ini";
	WritePrivateProfileString("settings","confirmRemove",
		theMenu->GetMenuState(CM_OPTIONSCONFIRM,MF_BYCOMMAND)
			== MF_CHECKED ? "1" : "0",iniPath);
	WritePrivateProfileString("settings","autoSave",
		theMenu->GetMenuState(CM_OPTIONSAUTOSAVE,MF_BYCOMMAND)
			== MF_CHECKED ? "1" : "0",iniPath);

  delete theMenu;
}

bool
TMainWindow::CanClose()
{
	TMenu *theMenu = new TMenu(GetApplication()->GetMainWindow()->GetMenu());

	if (theMenu->GetMenuState(CM_OPTIONSAUTOSAVE,MF_BYCOMMAND)
		 == MF_CHECKED)
	{
		SaveData();
		delete theMenu;
		return true;
	}

	delete theMenu;

	if (gModified)
	{
		int result = MessageBox("Would you like to save your changes?", "Quit",
							MB_YESNOCANCEL | MB_ICONQUESTION);
		if (result == IDCANCEL) return false;
		if (result == IDYES) SaveData();
	}

	return true;
}

void
TMainWindow::UpdateListBox()
{
	listbox->ClearList();
	int num = theList.GetItemsInContainer();
	for (int i=0;i < num ;i++)
		listbox->AddString(theList[i].Account());

	// disable remove button if there is nothing in the list
	if (num == 0)
	{
		removeButton->EnableWindow(FALSE);
		editButton->EnableWindow(FALSE);
		addButton->SetFocus();
	}
	else if (num == MAX_ENTRIES) {
		addButton->EnableWindow(FALSE);
		removeButton->EnableWindow(TRUE);
		editButton->EnableWindow(TRUE);
		listbox->SetFocus();
	}
	else {
		removeButton->EnableWindow(TRUE);
		editButton->EnableWindow(TRUE);
		listbox->SetFocus();
	}
}

void
TMainWindow::EvAddButton()
{
	TAddEditDialog *addDialog = new TAddEditDialog(this,
		GetApplication()->GetMainWindow(),"DIALOG_ADDEDIT",ADD);

	if(addDialog->Execute()==IDOK)
	{
		TPassListEntry entry;
		entry.Account(addDialog->Account());
		entry.Username(addDialog->Username());
		entry.Password(addDialog->Password());
		entry.Notes(addDialog->Notes());

		theList.Add(entry);

		UpdateListBox();
		listbox->SetSelString(entry.Account(),0);

		gModified = true;
	}
	else {}

	delete addDialog;
}

void
TMainWindow::EvRemoveButton()
{
	int selection = listbox->GetSelIndex();

	int count = listbox->GetCount();

	char account[MAX_ENTRY_SIZE+1];
	listbox->GetSelString(account,MAX_ENTRY_SIZE);

	TMenu *theMenu = new TMenu(GetApplication()->GetMainWindow()->GetMenu());

	if (theMenu->GetMenuState(CM_OPTIONSCONFIRM,MF_BYCOMMAND)
		 == MF_CHECKED)
	{
		strstream msg;
		msg << "Are you sure you want to remove \"" << account << "\"?" << '\0';

		if (MessageBox(msg.str(), "Remove",MB_YESNO | MB_ICONQUESTION) == IDNO) {
			delete theMenu;
			return;
		}
	}
	delete theMenu;

	theList.Destroy(selection);

	UpdateListBox();
	listbox->SetSelIndex(selection == count-1 ? selection -1 : selection);

  gModified = true;
}

void
TMainWindow::EvEditButton()
{
	int selection = listbox->GetSelIndex();

// 	strstream tmpmsg;
//	tmpmsg << "selection: " << selection << "\naccount:" <<
//		theList[selection].Account() << '\0';
//	MessageBox(tmpmsg.str(),"test");

	TEntry entry;
	strcpy(entry.account,theList[selection].Account());
	strcpy(entry.username,theList[selection].Username());
	strcpy(entry.password,theList[selection].Password());
	strcpy(entry.notes,theList[selection].Notes());

	TAddEditDialog *editDialog = new TAddEditDialog(this,
		GetApplication()->GetMainWindow(),"DIALOG_ADDEDIT",EDIT,&entry);

	if(editDialog->Execute()==IDOK)
	{
		theList.Destroy(selection);

		TPassListEntry entry;
		entry.Account(editDialog->Account());
		entry.Username(editDialog->Username());
		entry.Password(editDialog->Password());
		entry.Notes(editDialog->Notes());

		theList.Add(entry);

		UpdateListBox();

		listbox->SetSelIndex(selection);

		gModified = true;
	}
	else {}

	delete editDialog;
}

void
TMainWindow::EvQuitButton()
{
	GetApplication()->GetMainWindow()->SendMessage(WM_CLOSE,0,0);
}

void
TMainWindow::EvOptionsConfirm() {
 TMenu *theMenu = new TMenu(GetApplication()->GetMainWindow()->GetMenu());

 theMenu->CheckMenuItem(CM_OPTIONSCONFIRM,
	 theMenu->GetMenuState(CM_OPTIONSCONFIRM,MF_BYCOMMAND) == MF_CHECKED ?
	 MF_UNCHECKED:MF_CHECKED);

 delete theMenu;
}

void
TMainWindow::EvOptionsAutoSave()
{
 TMenu *theMenu = new TMenu(GetApplication()->GetMainWindow()->GetMenu());

 theMenu->CheckMenuItem(CM_OPTIONSAUTOSAVE,
	 theMenu->GetMenuState(CM_OPTIONSAUTOSAVE,MF_BYCOMMAND) == MF_CHECKED ?
	 MF_UNCHECKED:MF_CHECKED);

 delete theMenu;
}

void
TMainWindow::EvOptionsPassword()
{
	TChangePasswordDialog *dialog =
		new TChangePasswordDialog(this,"DIALOG_CHANGE_PASSWORD");

	if (dialog->Execute() == IDOK) {
		SetMainPassword(dialog->Password());
    gModified = true;
	}

	delete dialog;
}                                        

void
TMainWindow::EvHelpAbout()
{
	TDialog(this,"DIALOG_ABOUT").Execute();
}

void
TMainWindow::EvNotifyListBox(UINT code)
{
	if (code == LBN_DBLCLK)
		EvEditButton();
}

/*
LRESULT
TMainWindow::EvCompareItem(uint ctrlId, COMPAREITEMSTRUCT far& compareInfo)
{
	return stricmp(compareInfo->itemData1,compareInfo->itemData2);
}
*/

