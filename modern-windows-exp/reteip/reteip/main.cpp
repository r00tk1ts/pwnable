#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <conio.h>

int main()
{
	char name[32];
	_getch();	// for windbg to attach
	printf("Reading name from file...\n");

	FILE*f = fopen("../name.dat", "rb");
	if (!f)
	{
		printf("errno:%d str:%s\n", errno, strerror(errno));
		return -1;
	}

	fseek(f, 0L, SEEK_END);
	long bytes = ftell(f);
	fseek(f, 0L, SEEK_SET);
	fread(name, 1, bytes, f);
	name[bytes] = '\0';
	fclose(f);

	printf("Hi, %s!\n", name);

	return 0;
}

