#ifndef ADDEDIT_HPP
#define ADDEDIT_HPP

#include "main.hpp";

class TAddEditDialog : public TDialog {
	public:
		TAddEditDialog(TMainWindow *, TWindow */*parent*/,TResId /*resId*/,
			UINT /*type*/);
		TAddEditDialog(TMainWindow *, TWindow */*parent*/,TResId /*resId*/,
			UINT /*type*/,TEntry */*entry*/);
		~TAddEditDialog();
		void SetupWindow();

		char* Account() {return account;}
		char* Username() {return username;}
		char* Password() {return password;}
		char* Notes() {return notes;}

	protected:
		UINT type, selection;

		bool CanClose();

	private:
		TEdit *accountEdit,
				*usernameEdit,
				*passwordEdit,
				*notesEdit;

		char account[MAX_ENTRY_SIZE],
			  username[MAX_ENTRY_SIZE],
			  password[MAX_ENTRY_SIZE],
			  notes[MAX_NOTES_SIZE];

	  TMainWindow *myParent;
};

#endif