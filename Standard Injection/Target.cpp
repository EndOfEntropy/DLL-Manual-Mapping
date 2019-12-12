#include "pch.h"
#include <iostream>
#include "Windows.h"


using namespace std;

int main()
{
	int count = { 3 };
	for (int i = 0; i < count; i++)
	{
		cout << "Echo " << i << "\n";
	}

	std::cout << "Press any key, to exit!" << std::endl;
	std::cin.get();
	MessageBoxW(0, 0, 0, 0);

	return 0;
}
