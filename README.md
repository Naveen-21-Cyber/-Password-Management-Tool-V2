# 🔐 Enhanced Password Management System

A comprehensive, modern password manager built with Python and Tkinter, featuring advanced security tools, encrypted storage, and an intuitive dark-themed interface.

![image](https://github.com/user-attachments/assets/2651c48d-8b14-4147-a7cf-6698af238621)
![image](https://github.com/user-attachments/assets/e0704213-427e-47b1-935a-9404d955bec9)
![image](https://github.com/user-attachments/assets/bb39de8f-58a0-460c-9561-13982cec72fc)
![image](https://github.com/user-attachments/assets/421a9611-e686-4bc7-acb1-05187be67df1)
![image](https://github.com/user-attachments/assets/9bca5f69-eafd-4837-bc6f-3270396eb2e0)




## ✨ Features

### 🎲 Advanced Password Generator
- **Customizable Length**: Generate passwords from 8 to 128 characters
- **Character Set Control**: Choose from uppercase, lowercase, digits, and symbols
- **Smart Presets**: Ultra Secure, Business, PIN Code, and Memorable options
- **Ambiguous Character Filtering**: Exclude confusing characters like 0, O, 1, l
- **Cryptographically Secure**: Uses Python's `secrets` module for true randomness

### 🏦 Encrypted Password Vault
- **Military-Grade Encryption**: AES-256 encryption via Fernet
- **Secure Storage**: All passwords encrypted at rest
- **Easy Management**: Add, view, copy, and delete entries with a clean interface
- **Metadata Tracking**: Creation and modification timestamps
- **Import/Export**: JSON-based backup and restore functionality

### 🔍 Security Analysis Tools
- **Strength Assessment**: Comprehensive password analysis with entropy calculation
- **Breach Detection**: Check passwords against HaveIBeenPwned database
- **Pattern Recognition**: Detect common weaknesses and sequential patterns
- **Detailed Reporting**: Get actionable recommendations for password improvement

### 🛠️ Additional Security Tools
- **Passphrase Generator**: Create memorable word-based passwords
- **Text Encryption**: Encrypt sensitive text using the same secure algorithms
- **Vault Statistics**: Monitor your password security health
- **Duplicate Detection**: Find and manage duplicate passwords
- **Data Management**: Clean import/export with full data integrity

## 🚀 Quick Start

### Prerequisites
```bash
pip install cryptography requests pyperclip
```

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/enhanced-password-manager.git
cd enhanced-password-manager
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python PasswordMain.py
```

## 📱 Interface Overview

The application features a modern, dark-themed interface with four main tabs:

- **🎲 Generator**: Create secure passwords with advanced customization options
- **🏦 Vault**: Store and manage your passwords with military-grade encryption
- **🔍 Analyzer**: Analyze password strength and check for security breaches
- **🛠️ Tools**: Additional utilities for enhanced security management

## 🔒 Security Features

- **Zero-Knowledge Architecture**: Your master encryption key is stored locally
- **Fernet Encryption**: Symmetric encryption using AES 128 in CBC mode
- **Secure Random Generation**: Uses `secrets` module for cryptographically strong randomness
- **Password Breach Checking**: Integration with HaveIBeenPwned API (k-anonymity model)
- **Local Storage**: All data stored locally - no cloud dependencies

## 📋 System Requirements

- **Python**: 3.7 or higher
- **Operating System**: Windows, macOS, or Linux
- **Dependencies**: 
  - `tkinter` (usually included with Python)
  - `cryptography`
  - `requests`
  - `pyperclip`

## 🛡️ Privacy & Security

- **No Data Collection**: Zero telemetry or user tracking
- **Offline First**: Works completely offline (except breach checking)
- **Local Encryption Keys**: Your encryption key never leaves your device
- **Open Source**: Full transparency - review the code yourself

## 📊 Technical Details

### Encryption Specifications
- **Algorithm**: Fernet (AES 128 CBC + HMAC SHA256)
- **Key Derivation**: Fernet.generate_key() using os.urandom()
- **Authentication**: Built-in message authentication prevents tampering

### Password Generation
- **Entropy**: Configurable up to ~512 bits for maximum length passwords
- **Character Sets**: Full Unicode support with customizable character pools
- **Bias Prevention**: Uses `secrets.choice()` for uniform distribution

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided as-is for educational and personal use. While it implements strong security practices, users should evaluate it for their specific security requirements. Always backup your data and use additional security measures for critical applications.

## 🔗 Links

- [Report Bug](https://github.com/yourusername/enhanced-password-manager/issues)
- [Request Feature](https://github.com/yourusername/enhanced-password-manager/issues)
- [Security Policy](SECURITY.md)

---

⭐ **Star this repo if you find it useful!** ⭐
