#include <cctype>
#include <string>
#include <iostream>
using namespace std;
void encrypt(char * input, unsigned int offset) {
	for (int i = 0; input[i] != 0; i++) {
		if (input[i] == ' ')
			continue;
		char firstLetter = islower(input[i]) ? 'a' : 'A';
		unsigned int
			alphaOffset = input[i] - firstLetter,
			newAlphaOffset = alphaOffset+offset;
		input[i] = firstLetter + newAlphaOffset % 26;
	}
}
void decrypt(char * input, unsigned int offset) {
	for (int i = 0; input[i] != 0; i++) {
		if (input[i] == ' ')
			continue;
		char firstLetter = islower(input[i]) ? 'a' : 'A';
		unsigned int alphaOffset = input[i] - firstLetter;
		int newAlphaOffset = alphaOffset - offset;
		if (newAlphaOffset < 0) {
			newAlphaOffset += 26;
		}
		input[i] = firstLetter + (newAlphaOffset % 26);
	}
int main() {
	return 0;
}
