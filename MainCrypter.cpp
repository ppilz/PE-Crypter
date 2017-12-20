#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <iostream>
#include <fstream>
#include <stdint.h>
#include <cstring>
#include <cstdlib>
#include <stdlib.h>
#include "Crypto.h"

#define CRYPT_EXE_NAME "crypt.exe"

uint32_t key[4] = { 0xACB6,0x1344,0xEC90,0x285C };
const char *shellcode_name = "shellcode";

using namespace std;

/*
 * Open executable and write data (and size) into DATA struct
 */
bool OpenExecutable(string executable, DATA *data) {
	ifstream infile(executable, ios::in | ios::binary | ios::ate);
	if (infile.is_open())
	{
		data->size = infile.tellg();
		data->image = new char[data->size];
		infile.seekg(0, ios::beg);
		infile.read(data->image, data->size);
		infile.close();
		return true;
	}
	return false;
}

/*
 * Write the encrypted executable back.
 */
bool WriteExecutable(DATA *data) {
	ofstream f(CRYPT_EXE_NAME, std::ios::out | std::ios::binary);
	if (f.is_open()) {
		f.write((char*)data->image, data->size);
		f.close();
		return true;
	}
	return false;
}

/*
 * Generate the shellcode
 */
int generate_shellcode(std::string file) {
	FILE *sf; //executable
	FILE *f; //shellcode.h
	int i, c;
	sf = fopen(file.c_str(), "rb");
	if (sf == NULL) {
		fprintf(stderr, "fopen(%s) Failed. Could'nt open file.", file.c_str());
		return 1;
	}

	f = fopen("shellcode.h", "w");
	fprintf(f, "unsigned char %s[] = {", shellcode_name);

	// Write shellcode
	for (i = 0;; i++) {
		if ((c = fgetc(sf)) == EOF) break;
		if (i != 0) fprintf(f, ",");
		if ((i % 12) == 0) fprintf(f, "\n\t");
		fprintf(f, "0x%.2X", (unsigned char)c);
	}

	fprintf(f, "\n\t};\n");
	fprintf(f, "unsigned int size = %i;\n", i);

	fclose(sf);
	fclose(f);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [filepath]\n", argv[1]);
		return 1;
	}

	Crypto<CryptPolicyXOR> xor;
	
	DATA *data = (DATA*)malloc(sizeof(DATA));
	OpenExecutable(argv[1], data);
	cout << "Encrypting... " << endl;
	xor.doCrypt(data, key, sizeof(key)/sizeof(*key));
	cout << "Done." << endl;
	cout << "Creating encrypted executable..." << endl;
	WriteExecutable(data);
	cout << "Done. Crypted exe is: " << CRYPT_EXE_NAME << endl;
	cout << "Generating shellcode..." << endl;
	generate_shellcode(CRYPT_EXE_NAME);
	cout << "Done. Shellcode generated for: " << CRYPT_EXE_NAME << endl;
	system("pause");
	return 0;
}