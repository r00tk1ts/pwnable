#include <stdio.h>

int main()
{
	char name[32];
	printf("Reading name from file...\n");

	FILE *f = fopen("../name.dat", "rb");
	if (!f)
		return -1;
	fseek(f, 0L, SEEK_END);
	long bytes = ftell(f); 
	fseek(f, 0L, SEEK_SET);
	int pos = 0;
	while (pos < bytes){
		int len = bytes - pos > 200 ? 200 : bytes - pos;
		fread(name + pos, 1, len, f);
		pos += len;
	}
	name[bytes] = '\0';
	
	fclose(f);

	printf("Hi, %s!\n", name);
	return 0;
}