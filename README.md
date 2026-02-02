# 🔐 Encryption & Decryption Algorithms

[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?style=for-the-badge&logo=openssl&logoColor=white)](https://www.openssl.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**Implementation of secure encryption and decryption algorithms using the OpenSSL library.** *OpenSSL kütüphanesi kullanılarak güvenli şifreleme ve şifre çözme algoritmalarının uygulanması.*

🌍 **Language / Dil**
[🇺🇸 English](#-english) | [🇹🇷 Türkçe](#-türkçe)

---

<a name="-english"></a>
## 🇺🇸 English

### 🎯 About the Project

This repository contains C++ implementations of various cryptographic algorithms powered by the **OpenSSL** library. It serves as a practical guide and codebase for understanding how to implement secure data encryption and decryption in C++ applications.

The project is structured as a console application, making it easy to test and verify different encryption methods.

### ✨ Key Features

* **🛡️ OpenSSL Integration:** Utilizes the industry-standard OpenSSL library for robust security.
* **🔑 Encryption & Decryption:** Demonstrates the complete lifecycle of data protection.
* **💻 C++ Implementation:** High-performance code written in modern C++.
* **⚡ Visual Studio Ready:** Includes project files compatible with Visual Studio.

### 🛠 Prerequisites

Before running the project, ensure you have the following installed:

* **C++ Compiler:** GCC, Clang, or MSVC (Visual Studio).
* **OpenSSL Library:** Must be installed and linked to your project.
    * *Windows:* Can be installed via vcpkg or pre-compiled binaries.
    * *Linux:* `sudo apt-get install libssl-dev`

### 🚀 Installation & Build

#### Option 1: Visual Studio (Recommended for Windows)
1.  Clone the repository:
    ```bash
    git clone [https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git](https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git)
    ```
2.  Open the solution file inside the `ConsoleApplication4` folder.
3.  Ensure OpenSSL include and library directories are correctly configured in Project Properties.
4.  Build and Run (F5).

#### Option 2: Command Line (Linux/Mac)
1.  Navigate to the project directory.
2.  Compile using `g++` (linking crypto and ssl libraries):
    ```bash
    g++ main.cpp basic_encryption.cpp -o encryptor -lssl -lcrypto
    ```
3.  Run the application:
    ```bash
    ./encryptor
    ```

---

<a name="-türkçe"></a>
## 🇹🇷 Türkçe

### 🎯 Proje Hakkında

Bu depo, **OpenSSL** kütüphanesinden güç alan çeşitli kriptografik algoritmaların C++ uygulamalarını içerir. C++ uygulamalarında güvenli veri şifreleme (encryption) ve şifre çözme (decryption) işlemlerinin nasıl uygulanacağını anlamak için pratik bir rehber ve kod tabanı sunar.

Proje, farklı şifreleme yöntemlerini test etmeyi ve doğrulamayı kolaylaştıran bir konsol uygulaması olarak yapılandırılmıştır.

### ✨ Özellikler

* **🛡️ OpenSSL Entegrasyonu:** Endüstri standardı OpenSSL kütüphanesini kullanır.
* **🔑 Şifreleme ve Çözme:** Veri koruma döngüsünün (Encrypt/Decrypt) tamamını gösterir.
* **💻 C++ Uygulaması:** Modern C++ ile yazılmış yüksek performanslı kod.
* **⚡ Visual Studio Uyumlu:** Visual Studio ile doğrudan çalışmaya uygun proje dosyalarını içerir.

### 🛠 Gereksinimler

Projeyi çalıştırmadan önce aşağıdakilerin yüklü olduğundan emin olun:

* **C++ Derleyicisi:** GCC, Clang veya MSVC (Visual Studio).
* **OpenSSL Kütüphanesi:** Sisteme yüklü ve projeye linklenmiş olmalıdır.
    * *Windows:* vcpkg veya hazır binary dosyaları ile kurulabilir.
    * *Linux:* `sudo apt-get install libssl-dev`

### 🚀 Kurulum ve Çalıştırma

#### Seçenek 1: Visual Studio (Windows için Önerilen)
1.  Repoyu klonlayın:
    ```bash
    git clone [https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git](https://github.com/SweetRomeo/Encryption_Decryption_Algorithms.git)
    ```
2.  `ConsoleApplication4` klasörü içindeki çözüm (solution) dosyasını açın.
3.  Proje Özellikleri'nden (Project Properties) OpenSSL include ve library yollarının doğru yapılandırıldığından emin olun.
4.  Derleyin ve Çalıştırın (F5).

#### Seçenek 2: Komut Satırı (Linux/Mac)
1.  Proje dizinine gidin.
2.  `g++` kullanarak (ssl ve crypto kütüphanelerini bağlayarak) derleyin:
    ```bash
    g++ main.cpp basic_encryption.cpp -o encryptor -lssl -lcrypto
    ```
3.  Uygulamayı çalıştırın:
    ```bash
    ./encryptor
    ```

---

<div align="center">

**Developer:** [SweetRomeo](https://github.com/SweetRomeo)

</div>
