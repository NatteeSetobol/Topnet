#ifndef _MEMORYMAN_H_
#ifdef malloc
#undef malloc
#undef free
#endif

#ifndef bool 
#define bool unsigned int
#define true 1
#define false 0
#endif

#include <stdio.h>

struct minfo
{
	int size;
	void* address;
	struct minfo* next;
	struct minfo* prev;
};


struct memoryman
{
	struct minfo* head;
	struct minfo* current;
};

struct memoryman memorymanager={0};

void AddToMM(void* address, int size);
void* mmmalloc(size_t size);
void mmfree(void* address);
void freeall();

void mmfree(void* address)
{
	struct minfo* mpointer = memorymanager.head;

	bool empty=false;

	while (mpointer != NULL)
	{
		if ((int) mpointer->address ^  (int) address == 0)
		{
			struct minfo* temp = mpointer;
			if (mpointer->prev == NULL)
			{
				if (mpointer->next)
				{
					memorymanager.head = mpointer->next;
					memorymanager.head->prev=NULL;
				} else {
					empty = true;
				}
				
			} else {

				mpointer->prev->next = temp->next;
			}

			if (temp->address)
			{
				free(temp->address);
				temp->address = NULL;
			}

			if (temp)
			{
				free(temp);
				temp=NULL;
			}
			if(empty == true)  memorymanager.head = NULL;
			break;
		}
		mpointer = mpointer->next;
	}

}
void* mmmalloc(size_t size)
{
	void* result = malloc(size);
	AddToMM(result, size);
	return result;
}

void AddToMM(void* address, int size)
{
	if (memorymanager.head == NULL)
	{
		memorymanager.head = (struct minfo*) malloc(sizeof(struct minfo));
		memorymanager.head->size = size;
		memorymanager.head->address = address;
		memorymanager.head->next= NULL;
		memorymanager.head->prev = NULL;
		memorymanager.current = memorymanager.head;
		
	} else {
		memorymanager.current->next =(struct minfo*) malloc(sizeof(struct minfo));
		memorymanager.current->next->size = size;
		memorymanager.current->next->address = address;
		memorymanager.current->next->next = NULL;
		memorymanager.current->next->prev = memorymanager.current;
		memorymanager.current = memorymanager.current->next;
	}

}
/* this function show be added at the end of the program so it can delete everything that you have might fogotten to delete*/
void freeall()
{
	struct minfo* mpointer = memorymanager.head;

	int freed = 0;
	while (mpointer != NULL)
	{
		
		struct minfo* temp = mpointer;
		
		mpointer = mpointer->next;

		if (temp)
		{
			freed += temp->size;
			if (temp->address)
			{
				free(temp->address);
				temp->address = NULL;

			}	
			free(temp);
			temp=NULL;
		}
	}

	printf("freed %i\n",freed);
}

#define malloc(sz) mmmalloc(sz)
#define free(sz) mmfree(sz)

#endif
