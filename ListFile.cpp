#include <stdio.h>
#include <Windows.h>


int main(int argc, CHAR* argv[])
{
	WIN32_FIND_DATA* FindFileData;
	HANDLE hFind;

	while (1)
	{
		FindFileData = new WIN32_FIND_DATA;
		memset(FindFileData, 0, sizeof(WIN32_FIND_DATA));
		system("cls");
		hFind = FindFirstFileEx(argv[1], FindExInfoStandard, FindFileData, FindExSearchNameMatch, NULL, 0);
		if (hFind != NULL)
		{
			printf("%s\n", FindFileData->cFileName);
			memset(FindFileData, 0, sizeof(WIN32_FIND_DATA));
			while (FindNextFile(hFind, FindFileData))
			{
				printf("%s\n", FindFileData->cFileName);
			}
		}
		delete FindFileData;
		Sleep(1000);
	}
	return 0;
}