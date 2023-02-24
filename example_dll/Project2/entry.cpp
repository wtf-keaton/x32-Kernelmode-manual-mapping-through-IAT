#include <Windows.h>

bool WINAPI DllMain( HINSTANCE hinst, DWORD reason, void* reserved )
{

	MessageBoxA( 0, "Hello, world!", "!!!!!", 0 );

	return true;
}