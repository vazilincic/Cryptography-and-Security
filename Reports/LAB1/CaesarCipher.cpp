#include <iostream>
using namespace std;
string encrypt(string text, int s)
{
	string result = "";
	for (int i = 0; i < text.length(); i++) {
		if (isupper(text[i]))
			result += char(int(text[i] + s - 65) % 26 + 65);
		else
			result += char(int(text[i] + s - 97) % 26 + 97);
	}
	return result;
}
string decrypt(string text, int s)
{
	string result = "";
	for (int i = 0; i < text.length(); i++) {
		if (isupper(text[i]))
			result += char(int(text[i] + 26 - s - 65) % 26 + 65);
		else
			result += char(int(text[i] + 26 - s - 97) % 26 + 97);
	}
	return result;
}
int main()
{
  return 0;
}
