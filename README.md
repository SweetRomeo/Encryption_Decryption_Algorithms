# ⚡ CryptoBenchmark: Encryption & Decryption Timer

[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?style=for-the-badge&logo=openssl&logoColor=white)](https://www.openssl.org/)
[![Performance](https://img.shields.io/badge/Performance-Benchmark-brightgreen?style=for-the-badge&logo=speedtest&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**A desktop application to calculate and compare the execution time of various decryption algorithms.**
*Farklı şifre çözme algoritmalarının işlem sürelerini hesaplayan ve karşılaştıran masaüstü uygulaması.*

🌍 **Language / Dil**
[🇺🇸 English](#-english) | [🇹🇷 Türkçe](#-türkçe)

---

<a name="-english"></a>
## 🇺🇸 English

### 🎯 About the Project

This desktop application is designed to measure the performance of cryptographic algorithms. It utilizes the **OpenSSL** library to execute various encryption and decryption processes and precisely calculates the **time required for decryption**.

It serves as a benchmarking tool for developers and cryptography enthusiasts to understand the speed trade-offs between different algorithms (e.g., AES vs. DES) and key sizes.

### ✨ Key Features

* **⏱️ Precision Timing:** Accurately calculates the elapsed time for decryption operations in milliseconds/microseconds.
* **📊 Algorithm Benchmarking:** Compare the performance of different OpenSSL algorithms side-by-side.
* **💻 Desktop Environment:** Optimized to run on desktop platforms (Windows/Linux) for reliable CPU access.
* **🛡️ OpenSSL Implementation:** Uses industry-standard libraries for authentic performance metrics.

### 🛠 Tech Stack

* **Language:** C++ (High performance & direct memory management)
* **Library:** OpenSSL (Cryptographic functions)
* **IDE:** Visual Studio (Project structure is optimized for VS)

### 🚀 Installation & Build

#### Option 1: Visual Studio (Recommended)
1.  Clone the repository:
    ```bash
    git clone [https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git](https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git)
    ```
2.  Open the solution file in the `ConsoleApplication4` folder via Visual Studio.
3.  Ensure OpenSSL dependencies (Include & Lib folders) are correctly linked in Project Properties.
4.  Run the application (**Ctrl + F5**).

#### Option 2: Command Line (GCC/Clang)
1.  Navigate to the source directory.
2.  Compile with OpenSSL linking:
    ```bash
    g++ main.cpp basic_encryption.cpp -o crypto-bench -lssl -lcrypto
    ```
3.  Run the benchmark:
    ```bash
    ./crypto-bench
    ```

---

<a name="-türkçe"></a>
## 🇹🇷 Türkçe

### 🎯 Proje Hakkında

Bu masaüstü uygulaması, kriptografik algoritmaların performansını ölçmek için geliştirilmiştir. **OpenSSL** kütüphanesini kullanarak çeşitli şifreleme ve şifre çözme işlemlerini gerçekleştirir ve özellikle **şifre çözme (decryption) süresini** hassas bir şekilde hesaplar.

Geliştiriciler ve kriptografi meraklıları için farklı algoritmaların (örn. AES, DES vb.) hız farklarını ve sistem üzerindeki yükünü analiz etmeyi sağlayan bir **benchmark (kıyaslama)** aracıdır.

### ✨ Özellikler

* **⏱️ Hassas Süre Ölçümü:** Şifre çözme işleminin ne kadar sürdüğünü milisaniye/mikrosaniye cinsinden hesaplar.
* **📊 Algoritma Karşılaştırma:** Farklı algoritmaların hız performanslarını test etme imkanı sunar.
* **💻 Masaüstü Performansı:** İşlemci gücünü doğrudan kullanmak için masaüstü ortamına optimize edilmiştir.
* **🛡️ OpenSSL Altyapısı:** Gerçekçi sonuçlar için endüstri standardı kütüphaneleri kullanır.

### 🛠 Teknoloji Yığını

* **Dil:** C++ (Yüksek performans için)
* **Kütüphane:** OpenSSL (Şifreleme fonksiyonları için)
* **IDE:** Visual Studio (Proje yapısı VS için hazırdır)

### 🚀 Kurulum ve Çalıştırma

#### Seçenek 1: Visual Studio (Önerilen)
1.  Repoyu bilgisayarınıza indirin:
    ```bash
    git clone [https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git](https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git)
    ```
2.  `ConsoleApplication4` klasöründeki çözüm dosyasını Visual Studio ile açın.
3.  Proje ayarlarında OpenSSL kütüphanesinin (Include ve Lib yolları) tanımlı olduğundan emin olun.
4.  Uygulamayı çalıştırın (**Ctrl + F5**).

#### Seçenek 2: Komut Satırı (GCC)
1.  Kaynak kodun olduğu dizine gidin.
2.  OpenSSL kütüphanesini bağlayarak derleyin:
    ```bash
    g++ main.cpp basic_encryption.cpp -o crypto-bench -lssl -lcrypto
    ```
3.  Testi başlatın:
    ```bash
    ./crypto-bench
    ```

---

<div align="center">

**Developer:** [SweetRomeo](https://github.com/SweetRomeo)

</div>
