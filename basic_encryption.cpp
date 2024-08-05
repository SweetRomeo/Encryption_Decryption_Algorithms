/*-------------------------------------------------------
Aşağıdaki örnekte vector sınıfı için const bir sınıf nesnesi
yaratılması durumunda vector sınıfının front ve back fonksiyonları
çağrılarak elemanlarının değiştirilmesi syntax hatasına neden olur.
--------------------------------------------------------*/
#include <iostream>
#include <fstream>

using namespace std;

void encrypText(string& text, int key) {
    for (char & i : text) {
        i += static_cast<char>(key);
    }
}

void decrypText(string& text, int key) {
    for (char& i : text) {
        i -= static_cast<char>(key);
    }
}


int main()
{
    fstream ios{"berke.txt", ios::binary};
    string text = "Hello World!";
    encrypText(text,10);
    cout << "Encrypted Text : " << text << '\n';
    decrypText(text, 10);
    cout << "Decrypted Text : " << text << '\n';

}