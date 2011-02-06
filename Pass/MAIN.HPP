#ifndef MAIN_HPP
#define MAIN_HPP

class TMainWindow : public TDialog {
	public:
	 TMainWindow();
	 ~TMainWindow();
	 void SetupWindow();
	 bool CanClose();
	 void SetMainPassword(char *);

	protected:
		TListBox *listbox;
		TButton *removeButton,
    				*editButton,
						*addButton;
		char mainPassword[MAX_ENTRY_SIZE];

		void LoadData();
		void SaveData();
		void Encrypt(BYTE */*data*/,UINT /*size*/,BYTE */*password*/);
		void Decrypt(BYTE */*data*/,UINT /*size*/,BYTE */*password*/);
		void UpdateListBox();
		void EvAddButton();
		void EvRemoveButton();
		void EvEditButton();
		void EvQuitButton();
		void EvOptionsConfirm();
		void EvOptionsAutoSave();
		void EvOptionsPassword();
		void EvHelpAbout();
		void EvNotifyListBox(UINT /*code*/);

	public:
      bool Duplicate(char *);

	DECLARE_RESPONSE_TABLE(TMainWindow);
};

#endif