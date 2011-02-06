#ifndef PASSDLG_HPP
#define PASSDLG_HPP

class TWelcomeDialog : public TDialog {
	public:
		TWelcomeDialog(TWindow */*parent*/,TResId /*resId*/);
		~TWelcomeDialog();

		char *Password() {return password; }

	protected:
		bool CanClose();

	private:
		TEdit *passwordEdit1,
					*passwordEdit2;

		char password[MAX_ENTRY_SIZE];
};

class TEnterPasswordDialog : public TDialog {
	public:
		TEnterPasswordDialog(TWindow */*parent*/,TResId /*resId*/);
		~TEnterPasswordDialog();

    char *Password() {return password;}

	protected:
		bool CanClose();

	private:
		TEdit *passwordEdit;

		char password[MAX_ENTRY_SIZE];
    int login_attempts;
};

class TChangePasswordDialog : public TDialog {
	public:
		TChangePasswordDialog(TWindow */*parent*/,TResId /*resId*/);
		~TChangePasswordDialog();

		char *Password() {return password;}

	protected:
		bool CanClose();

	private:
    char password[MAX_ENTRY_SIZE];
		TEdit *passwordEdit1,
					*passwordEdit2;
};

#endif