# 🔐 Secure LAN Chat System v2.1

A hybrid-encrypted, secure peer-to-peer chat application developed using **Python** and **PyQt5**. The system provides secure communication over a Local Area Network (LAN) by combining encryption, authentication, and message integrity mechanisms to protect user conversations from unauthorized access and tampering.

The application implements a multi-layer security architecture including **hybrid encryption**, **HMAC-based integrity verification**, and **PBKDF2-HMAC-SHA256 password hashing** to ensure confidentiality, authenticity, and secure user management.

---

# 📌 Overview

Traditional LAN chat applications often transmit messages without sufficient protection, making them vulnerable to eavesdropping, message modification, and unauthorized access.

The **Secure LAN Chat System** addresses these issues by introducing cryptographic security mechanisms:

- Secure user authentication using salted password hashing
- Encrypted message transmission between clients
- Message integrity verification using HMAC
- Real-time message delivery through server-side push notifications
- Persistent storage using SQLite database
- Modern graphical interface using PyQt5

The system is designed for secure communication within a trusted Local Area Network environment.

---

# 🚀 Features

## 🔒 Hybrid Encryption

The system applies a hybrid encryption approach by combining symmetric and asymmetric encryption concepts:

- Symmetric encryption provides efficient message confidentiality.
- Asymmetric encryption concepts are used for secure key management.
- Encrypted messages remain unreadable even if network traffic is intercepted.

---

## 🛡 Message Integrity Protection

The system uses **HMAC (Hash-based Message Authentication Code)** to verify message authenticity and detect unauthorized modifications.

Security benefits:

- Detects message tampering during transmission
- Ensures received messages are identical to the original messages
- Protects against man-in-the-middle modification attacks

---

## 🔑 Secure Password Storage

User passwords are never stored in plaintext.

The system implements:

- PBKDF2-HMAC-SHA256 password hashing
- Unique random salts for each user
- 100,000 hashing iterations

This provides resistance against:

- Brute-force attacks
- Dictionary attacks
- Rainbow table attacks

---

## 💬 Real-Time Messaging

The application supports instant message delivery using server-side push notifications.

Features include:

- Real-time communication between connected users
- No continuous client polling required
- Efficient message routing through the server

---

## 🎨 Modern Graphical User Interface

The client application provides a clean and user-friendly interface developed with **PyQt5**.

Interface features:

- Light-themed design
- Responsive chat layout
- Modern messaging application style
- User-friendly controls

---

# 🏗 System Architecture

The system follows a client-server architecture consisting of three main components:

```
                 +----------------+
                 |   Chat Client  |
                 |   (PyQt5 UI)   |
                 +-------+--------+
                         |
                         |
                 Encrypted Connection
                         |
                         |
                 +-------+--------+
                 |  Chat Server   |
                 | Authentication |
                 | Message Router |
                 +-------+--------+
                         |
                         |
                 +-------+--------+
                 | SQLite Database|
                 | User & Messages|
                 +----------------+
```

---

# 🛡 Security Architecture

The system applies multiple security layers to protect user information.

## Authentication

User credentials are protected using:

- PBKDF2-HMAC-SHA256 hashing algorithm
- 100,000 computation iterations
- Random salt generation

Password storage process:

```
User Password
      |
      v
Generate Random Salt
      |
      v
PBKDF2-HMAC-SHA256
      |
      v
Secure Password Hash
      |
      v
Database Storage
```

---

## Confidentiality

Messages are encrypted before transmission.

Security process:

```
Plain Message
      |
      v
Encryption Algorithm
      |
      v
Encrypted Ciphertext
      |
      v
Network Transmission
      |
      v
Decryption by Receiver
```

Even if attackers intercept network traffic, the encrypted content cannot be understood without the required cryptographic keys.

---

## Integrity Verification

Each encrypted message contains an HMAC signature.

Verification process:

```
Received Message
       |
       v
Generate HMAC Signature
       |
       v
Compare with Original HMAC
       |
       |
  +----+----+
  |         |
Match    Mismatch
  |         |
Accept   Reject
Message  Message
```

If the encrypted message is modified during transmission, the system detects the change and rejects the corrupted message.

---

# 📋 Prerequisites

## Required Software

- Python 3.7 or above
- pip package manager

## Required Library

Install PyQt5:

```bash
pip install PyQt5
```

---

# 🛠 Installation

## 1. Clone the Repository

```bash
git clone <repository-url>
```

Navigate into the project folder:

```bash
cd Secure-LAN-Chat-System
```

---

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

## Start the Server

The server manages:

- User authentication
- Database operations
- Client connections
- Message routing
- Encrypted message storage

Run:

```bash
python secure_lan_chat.py --server --port 5555
```

Default port:

```
5555
```

---

## Launch Client

Each user connects to the server using the server machine's IP address.

Run:

```bash
python secure_lan_chat.py --client --host <server_IP>
```

Example:

```bash
python secure_lan_chat.py --client --host 192.168.1.10
```

---

# 📂 Project Structure

```
Secure-LAN-Chat-System/
│
├── secure_lan_chat.py
│
├── HybridCrypto
│   ├── Key generation
│   ├── Encryption
│   ├── Decryption
│   └── Password hashing
│
├── ChatDatabase
│   ├── SQLite connection
│   ├── User management
│   └── Message storage
│
├── ChatServer
│   ├── Client connection handling
│   ├── Authentication
│   ├── Message routing
│   └── Push notification system
│
├── ChatClient
│   ├── PyQt5 interface
│   ├── Network communication
│   └── Message decryption
│
└── README.md
```

---

# 🔧 Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Core application development |
| PyQt5 | Graphical user interface |
| SQLite | Database storage |
| HMAC | Message integrity verification |
| PBKDF2-HMAC-SHA256 | Password security |
| Socket Programming | LAN communication |
| Cryptography Concepts | Secure message protection |

---

# 🔍 Security Features Summary

| Security Feature | Implementation |
|---|---|
| Authentication | PBKDF2-HMAC-SHA256 password hashing |
| Password Protection | Salted hash storage |
| Message Confidentiality | Hybrid encryption approach |
| Message Integrity | HMAC verification |
| Data Persistence | SQLite database |
| Secure Communication | Encrypted LAN transmission |

---

# 📈 Future Improvements

Possible enhancements include:

- Implementing fully standardized AES-256-GCM encryption
- Adding RSA/ECC key exchange
- Supporting file transfer with encryption
- Adding multi-factor authentication
- Improving user presence status
- Adding end-to-end encryption without server access

---

# 👨‍💻 Author

Developed as a secure communication system project focusing on:

- Network security
- Cryptography implementation
- Secure software development
- Real-time application design

---

# 📄 License

This project is developed for educational and research purposes.
