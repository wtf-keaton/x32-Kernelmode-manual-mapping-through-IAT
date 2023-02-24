#include "mmap.hpp"

int main(int argc, char **argv) { 
	mmap mapper(INJECTION_TYPE::USERMODE);

	if (!mapper.attach_to_process("ac_client.exe"))
		return 1;

	if (!mapper.load_dll(u8"D:\\example_dll.dll"))
		return 1;

	if (!mapper.inject())
		return 1;

	LOG("\nPress any key to close.");
	std::getchar();
	 
	return 0;
}