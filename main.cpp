#include <iostream>
#include <string>
#include <random>
#include <unordered_set>

void randomFill(std::string& text, int size) {
    using namespace std;
    string alphaBeth = "abcdefghijklmnqprstuvwxyz";
    std::cout << alphaBeth.size() << '\n';
    random_device rd;
    mt19937 mt(rd());
    uniform_int_distribution<int> ist(0, alphaBeth.size() - 1);
    for (int i = 0; i < size; ++i) {
        auto iter = text.begin();
        *iter = alphaBeth.at(ist(mt));
        text.push_back(*iter);
    }
}

int main() {
    std::vector<std::pair<std::string, bool>> Algorithms = {{ "RSA", false },{"DSA", false},{"DH", false},{"Chacha20", true},
         { "Camellia", true}, {"DES", true}, {"RC4", true}, {"AES", true}, {"Seed", true}};
    for(auto& [AlgoName, isSimetric] : Algorithms) {
        std::cout << "Algorithm Name : " << AlgoName << '\n';
        std::cout << "Algorithm Type : " << (isSimetric ? "Simetric" : "Asimetric") << '\n';
    }
}