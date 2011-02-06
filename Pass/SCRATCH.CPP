int sort_function( const void *a, const void *b);
char list[5][4] = { "cat", "car", "cab", "cap", "can" };

int main(void)
{
   int  x;

	 qsort((void *)list, 5, sizeof(list[0]), sort_function);
	 for (x = 0; x < 5; x++)
      printf("%s\n", list[x]);
   return 0;
}

int sort_function( const void *a, const void *b)
{
   return( strcmp((char *)a,(char *)b) );
}

class TPassList {
	public:
		TPassList();
		TListEntry entry[MAX_ENTRIES];
		void Add(TListEntry *);
		UINT Size();
		void Sort();

	private:
		UINT index;
		int sort_function( const void *, const void *);
}

void TPassList::TPassList()
{
	index = 0;
}

void TPassList::Add(TListEntry *new)
{
	entry[index].service = new->service;
	entry[index].username = new->username;
	entry[index].password = new->password;
}

void TPassList::Sort()
{
	 qsort((void *)list, 5, sizeof(list[0]), sort_function);

}

int TPassList::sort_function( const void *a, const void *b)


TPassList theList;
