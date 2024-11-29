#include "Loader.h"

//Function pointer
typedef void (*MessageFncPtr)();

int main()
{
	LPVOID lpModule = MemoryLoader::LoadDLL((LPSTR)"test.dll");
	if (lpModule == NULL)
		return -1;

	MessageFncPtr MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddress((LPVOID)lpModule, (const LPSTR)"Message");
	if (MessageFnc == NULL)
		return -1;

	MessageFnc();

	MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddressByOrdinal((LPVOID)lpModule, 1);
	if (MessageFnc == NULL)
		return -1;

	MessageFnc();

	MemoryLoader::FreeDLL(lpModule);

	system("PAUSE");

	return 0;
}