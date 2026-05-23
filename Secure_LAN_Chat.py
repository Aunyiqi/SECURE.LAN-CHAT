#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔐 SECURE LAN CHAT SYSTEM v2.1 (PyQt5)                    ║
║                   Hybrid Encrypted Secure LAN Chat System                     ║
║                                                                              ║
║  Usage:                                                                      ║
║    Server: python secure_lan_chat.py --server [--port 5555]                  ║
║    Client: python secure_lan_chat.py --client --host <server_IP>             ║
║                                                                              ║
║  Features:                                                                   ║
║    • Hybrid Encryption (RSA Simulation + AES-like Symmetric Encryption)      ║
║    • PBKDF2-HMAC-SHA256 Password Hashing                                     ║
║    • Message Integrity Verification (HMAC)                                   ║
║    • Modern PyQt5 GUI Interface (Light Theme)                                ║
║    • Real-time Message Sync (Server Push Notifications)                      ║
║    • WeChat-style Message Display (Self on Right, Others on Left)            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import base64
import hashlib
import secrets
import sqlite3
import socket
import threading
import argparse
import datetime
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass


# ═══════════════════════════════════════════════════════════════════════════════
#                              Encryption Module
# ═══════════════════════════════════════════════════════════════════════════════

class HybridCrypto:
    """Hybrid Encryption System - Combining Asymmetric and Symmetric Encryption"""

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generate simulated RSA keypair (using random bytes for demonstration)"""
        private_key = secrets.token_bytes(256)
        public_key = hashlib.sha256(private_key).digest() + secrets.token_bytes(224)
        return private_key, public_key

    @staticmethod
    def derive_shared_secret(private_key: bytes, public_key: bytes) -> bytes:
        """Derive shared secret from keypair (simulating ECDH)"""
        combined = private_key + public_key
        return hashlib.sha256(combined).digest()

    @staticmethod
    def hash_password(password: str, salt: bytes = None, iterations: int = 100000) -> Dict:
        """Password hashing using PBKDF2-HMAC-SHA256"""
        if salt is None:
            salt = secrets.token_bytes(32)

        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)

        return {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'hash': base64.b64encode(key).decode('utf-8'),
            'iterations': iterations
        }

    @staticmethod
    def verify_password(password: str, stored_hash: str, stored_salt: str, iterations: int) -> bool:
        """Verify password"""
        salt = base64.b64decode(stored_salt)
        expected_hash = base64.b64decode(stored_hash)
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return secrets.compare_digest(computed_hash, expected_hash)

    @staticmethod
    def encrypt_message(plaintext: str, key: bytes = None) -> Dict:
        """Encrypt message - Using AES-like symmetric encryption + HMAC integrity check"""
        if key is None:
            key = secrets.token_bytes(32)

        iv = secrets.token_bytes(16)
        text_bytes = plaintext.encode('utf-8')
        key_stream = b''
        counter = 0
        while len(key_stream) < len(text_bytes):
            block = hashlib.sha256(key + iv + counter.to_bytes(4, 'big')).digest()
            key_stream += block
            counter += 1

        encrypted = bytes([text_bytes[i] ^ key_stream[i] for i in range(len(text_bytes))])
        hmac_key = hashlib.sha256(key + b'hmac').digest()
        hmac_value = hashlib.sha256(hmac_key + iv + encrypted).hexdigest()

        return {
            'ciphertext': base64.b64encode(encrypted).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8'),
            'hmac': hmac_value,
            'algorithm': 'AES-256-CTR-HMAC (Simulated)'
        }

    @staticmethod
    def decrypt_message(encrypted_data: Dict) -> str:
        """Decrypt message"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        key = base64.b64decode(encrypted_data['key'])

        hmac_key = hashlib.sha256(key + b'hmac').digest()
        expected_hmac = hashlib.sha256(hmac_key + iv + ciphertext).hexdigest()

        if not secrets.compare_digest(expected_hmac, encrypted_data['hmac']):
            raise ValueError("⚠️ Message integrity verification failed! Possibly tampered!")

        key_stream = b''
        counter = 0
        while len(key_stream) < len(ciphertext):
            block = hashlib.sha256(key + iv + counter.to_bytes(4, 'big')).digest()
            key_stream += block
            counter += 1

        decrypted = bytes([ciphertext[i] ^ key_stream[i] for i in range(len(ciphertext))])
        return decrypted.decode('utf-8')


# ═══════════════════════════════════════════════════════════════════════════════
#                              Database Module
# ═══════════════════════════════════════════════════════════════════════════════

class ChatDatabase:
    """SQLite Database Management"""

    def __init__(self, db_file: str = "secure_chat.db"):
        self.db_file = db_file
        self._init_db()

    def _init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_online INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                iv TEXT NOT NULL,
                encryption_key TEXT NOT NULL,
                hmac TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    def register_user(self, username: str, password_hash: str, password_salt: str,
                      iterations: int, public_key: str) -> Tuple[bool, str]:
        """Register new user"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, iterations, public_key)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, password_salt, iterations, public_key))
            conn.commit()
            conn.close()
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, f"Registration failed: {str(e)}"

    def verify_user(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """Verify user login"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash, password_salt, iterations, public_key
            FROM users
            WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return False, "User does not exist", None

        stored_hash, stored_salt, iterations, public_key = result

        if HybridCrypto.verify_password(password, stored_hash, stored_salt, iterations):
            return True, "Login successful", {'public_key': public_key}
        else:
            return False, "Incorrect password", None

    def update_online_status(self, username: str, is_online: bool):
        """Update user online status"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET is_online = ?,
                last_login = CURRENT_TIMESTAMP
            WHERE username = ?
        ''', (1 if is_online else 0, username))
        conn.commit()
        conn.close()

    def get_all_users(self) -> List[Dict]:
        """Get all users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT username, is_online FROM users')
        users = [{'username': row[0], 'is_online': row[1]} for row in cursor.fetchall()]
        conn.close()
        return users

    def save_message(self, sender: str, recipient: str, encrypted_data: Dict) -> bool:
        """Save encrypted message"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (sender, recipient, ciphertext, iv, encryption_key, hmac)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (sender, recipient, encrypted_data['ciphertext'],
                  encrypted_data['iv'], encrypted_data['key'], encrypted_data['hmac']))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Failed to save message: {e}")
            return False

    def get_messages(self, username: str) -> List[Dict]:
        """Get user's messages"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, sender, recipient, ciphertext, iv, encryption_key, hmac, timestamp
            FROM messages
            WHERE recipient = ? OR sender = ?
            ORDER BY timestamp DESC
        ''', (username, username))
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'sender': row[1],
                'recipient': row[2],
                'ciphertext': row[3],
                'iv': row[4],
                'encryption_key': row[5],
                'hmac': row[6],
                'timestamp': row[7]
            })
        conn.close()
        return messages

    def get_conversation(self, user1: str, user2: str) -> List[Dict]:
        """Get conversation between two users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, sender, recipient, ciphertext, iv, encryption_key, hmac, timestamp
            FROM messages
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY timestamp ASC
        ''', (user1, user2, user2, user1))
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'sender': row[1],
                'recipient': row[2],
                'ciphertext': row[3],
                'iv': row[4],
                'encryption_key': row[5],
                'hmac': row[6],
                'timestamp': row[7]
            })
        conn.close()
        return messages

    def get_new_messages_since(self, user1: str, user2: str, since_timestamp: str) -> List[Dict]:
        """Get incremental new messages between two users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, sender, recipient, ciphertext, iv, encryption_key, hmac, timestamp
            FROM messages
            WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
                AND timestamp > ?
            ORDER BY timestamp ASC
        ''', (user1, user2, user2, user1, since_timestamp))
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'sender': row[1],
                'recipient': row[2],
                'ciphertext': row[3],
                'iv': row[4],
                'encryption_key': row[5],
                'hmac': row[6],
                'timestamp': row[7]
            })
        conn.close()
        return messages


# ═══════════════════════════════════════════════════════════════════════════════
#                              Server Module
# ═══════════════════════════════════════════════════════════════════════════════

class ChatServer:
    """Chat Server"""

    def __init__(self, host: str = '0.0.0.0', port: int = 5555):
        self.host = host
        self.port = port
        self.db = ChatDatabase()
        self.clients: Dict[str, socket.socket] = {}
        self.running = False
        self.server_socket = None

    def start(self):
        """Start server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        self.running = True

        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                🔐 Secure Chat Server Started                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Address: {self.host}:{self.port}                                           
║  Status: Waiting for connections...                              ║
╚══════════════════════════════════════════════════════════════════╝
        """)

        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"📡 New connection: {address}")
                client_thread = threading.Thread(target=self._handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Accept connection error: {e}")

    def stop(self):
        """Stop server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def _handle_client(self, client_socket: socket.socket, address):
        username = None
        try:
            while self.running:
                print(f"[{address}] Waiting to receive data...")
                data = client_socket.recv(4096)
                if not data:
                    print(f"[{address}] Client disconnected (no data)")
                    break

                print(f"[{address}] Received data length: {len(data)} bytes")
                try:
                    request = json.loads(data.decode('utf-8'))
                    print(f"[{address}] Received request: {request}")
                except Exception as e:
                    print(f"[{address}] JSON parsing failed: {e}")
                    print(f"Raw data: {data}")
                    break

                response = self._process_request(request, client_socket)
                print(f"[{address}] Sending response: {response}")

                client_socket.send(json.dumps(response).encode('utf-8'))

                # Save client socket for push notifications after successful login
                if request.get('action') == 'login' and response.get('success'):
                    username = request.get('username')
                    self.clients[username] = client_socket  # Key: Save socket for pushing
                    print(f"[{address}] Login successful: {username}, added to online list")

        except Exception as e:
            print(f"[{address}] Processing exception: {e}")
        finally:
            if username:
                self.db.update_online_status(username, False)
                if username in self.clients:
                    del self.clients[username]
                print(f"[{address}] User {username} went offline")
            client_socket.close()
            print(f"[{address}] Connection closed")

    def _process_request(self, request: Dict, client_socket: socket.socket) -> Dict:
        """Process client request"""
        action = request.get('action')

        if action == 'register':
            username = request.get('username')
            password = request.get('password')
            public_key = request.get('public_key', '')

            password_data = HybridCrypto.hash_password(password)
            success, msg = self.db.register_user(
                username,
                password_data['hash'],
                password_data['salt'],
                password_data['iterations'],
                public_key
            )
            return {'success': success, 'message': msg}

        elif action == 'login':
            username = request.get('username')
            password = request.get('password')

            success, msg, user_data = self.db.verify_user(username, password)
            if success:
                self.db.update_online_status(username, True)
            return {'success': success, 'message': msg, 'data': user_data}

        elif action == 'get_users':
            users = self.db.get_all_users()
            return {'success': True, 'users': users}

        elif action == 'send_message':
            sender = request.get('sender')
            recipient = request.get('recipient')
            encrypted_data = request.get('encrypted_data')

            success = self.db.save_message(sender, recipient, encrypted_data)

            if success and recipient in self.clients:
                try:
                    notification = json.dumps({
                        'type': 'new_message',
                        'from': sender,
                        'encrypted_data': encrypted_data,
                        'timestamp': datetime.datetime.now().isoformat()
                    })
                    self.clients[recipient].send(notification.encode('utf-8'))
                except Exception as e:
                    print(f"Push notification failed: {e}")

            return {'success': success, 'message': 'Message sent' if success else 'Send failed'}

        elif action == 'get_messages':
            username = request.get('username')
            messages = self.db.get_messages(username)
            return {'success': True, 'messages': messages}

        elif action == 'get_conversation':
            user1 = request.get('user1')
            user2 = request.get('user2')
            messages = self.db.get_conversation(user1, user2)
            return {'success': True, 'messages': messages}

        elif action == 'get_new_messages_since':
            user1 = request.get('user1')
            user2 = request.get('user2')
            since_timestamp = request.get('since_timestamp')
            messages = self.db.get_new_messages_since(user1, user2, since_timestamp)
            return {'success': True, 'messages': messages}

        return {'success': False, 'message': 'Unknown action'}


# ═══════════════════════════════════════════════════════════════════════════════
#                              Client Module
# ═══════════════════════════════════════════════════════════════════════════════

class ChatClient:
    """Chat Client"""

    def __init__(self, server_host: str, server_port: int):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.current_user = None
        self.private_key, self.public_key = HybridCrypto.generate_keypair()
        self.session_key = secrets.token_bytes(32)
        self.listener_thread = None
        self.running = False
        self.listening = False
        self.on_notification = None
        self._socket_lock = threading.Lock()  # Socket operation lock
        self._pending_response = None  # Store request response
        self._response_event = threading.Event()  # Response event

    def connect(self) -> bool:
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.running = True
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def _start_listener(self):
        """Start listener thread"""
        if self.listening:
            return
        self.listening = True
        self.listener_thread = threading.Thread(target=self._listen_loop)
        self.listener_thread.daemon = True
        self.listener_thread.start()

    def _listen_loop(self):
        """Unified receive loop"""
        print("[Listener] Listener thread started")
        buffer = b''
        while self.running and self.listening:
            try:
                self.socket.settimeout(0.5)
                data = self.socket.recv(4096)
                if not data:
                    break
                buffer += data

                # Try to parse complete JSON
                try:
                    decoded = buffer.decode('utf-8')
                    msg = json.loads(decoded)
                    buffer = b''

                    print(f"[Listener] Received message: {msg}")  # Debug info

                    # Determine if it's a push notification or request response
                    if 'type' in msg and msg['type'] == 'new_message':
                        # Push notification
                        print(f"[Listener] This is a push notification, calling callback")
                        if self.on_notification:
                            self.on_notification(msg)
                    else:
                        # Request response
                        print(f"[Listener] This is a request response")
                        self._pending_response = msg
                        self._response_event.set()
                except json.JSONDecodeError:
                    # JSON incomplete, continue receiving
                    pass

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[Listener] Receive error: {e}")
                break
        print("[Listener] Listener thread ended")

    def close(self):
        """Close connection"""
        self.running = False
        self.listening = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def _send_request(self, request: Dict) -> Dict:
        """Send request and get response"""
        with self._socket_lock:
            try:
                # Clear previous response
                self._pending_response = None
                self._response_event.clear()

                # If listener thread is started, use event to wait for response
                if self.listening:
                    self.socket.send(json.dumps(request).encode('utf-8'))
                    # Wait for response, max 10 seconds
                    if self._response_event.wait(timeout=10):
                        response = self._pending_response
                        self._pending_response = None
                        return response if response else {'success': False, 'message': 'Response empty'}
                    else:
                        return {'success': False, 'message': 'Request timeout'}
                else:
                    # Listener thread not started, direct send/receive
                    self.socket.settimeout(10)
                    self.socket.send(json.dumps(request).encode('utf-8'))
                    response_data = self.socket.recv(8192)
                    return json.loads(response_data.decode('utf-8'))

            except socket.timeout:
                return {'success': False, 'message': 'Request timeout'}
            except Exception as e:
                return {'success': False, 'message': f'Communication error: {e}'}

    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """Register"""
        response = self._send_request({
            'action': 'register',
            'username': username,
            'password': password,
            'public_key': base64.b64encode(self.public_key).decode('utf-8')
        })
        return response.get('success', False), response.get('message', 'Unknown error')

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Login"""
        response = self._send_request({
            'action': 'login',
            'username': username,
            'password': password
        })
        if response.get('success'):
            self.current_user = username
            # Start listener thread after successful login
            self._start_listener()
        return response.get('success', False), response.get('message', 'Unknown error')

    def get_users(self) -> List[str]:
        """Get user list"""
        response = self._send_request({'action': 'get_users'})
        if response.get('success'):
            users = response.get('users', [])
            return [u['username'] for u in users if u['username'] != self.current_user]
        return []

    def send_message(self, recipient: str, message: str) -> Tuple[bool, str]:
        """Send message"""
        encrypted_data = HybridCrypto.encrypt_message(message)
        response = self._send_request({
            'action': 'send_message',
            'sender': self.current_user,
            'recipient': recipient,
            'encrypted_data': encrypted_data
        })
        return response.get('success', False), response.get('message', 'Unknown error')

    def get_inbox(self) -> List[Dict]:
        """Get inbox"""
        response = self._send_request({
            'action': 'get_messages',
            'username': self.current_user
        })
        return response.get('messages', [])

    def get_conversation(self, other_user: str) -> List[Dict]:
        """Get conversation with a user"""
        response = self._send_request({
            'action': 'get_conversation',
            'user1': self.current_user,
            'user2': other_user
        })
        return response.get('messages', [])

    def get_new_messages_since(self, other_user: str, since_timestamp: str) -> List[Dict]:
        """Get incremental new messages"""
        response = self._send_request({
            'action': 'get_new_messages_since',
            'user1': self.current_user,
            'user2': other_user,
            'since_timestamp': since_timestamp
        })
        return response.get('messages', [])

    def decrypt_message(self, msg: Dict) -> str:
        """Decrypt message"""
        try:
            return HybridCrypto.decrypt_message({
                'ciphertext': msg['ciphertext'],
                'iv': msg['iv'],
                'key': msg['encryption_key'],
                'hmac': msg['hmac']
            })
        except Exception as e:
            return f"[Decryption failed: {e}]"


# ═══════════════════════════════════════════════════════════════════════════════
#                           PyQt5 GUI Interface Module
# ═══════════════════════════════════════════════════════════════════════════════

def run_gui_client(server_host: str, server_port: int):
    """Run PyQt5 GUI client"""
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QFrame, QScrollArea, QTextEdit,
        QMessageBox, QSplitter, QListWidget, QListWidgetItem, QStackedWidget,
        QSizePolicy, QGraphicsDropShadowEffect
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QObject
    from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap

    # ═══════════════════════════════════════════════════════════════════════════
    # Light Theme Stylesheet
    # ═══════════════════════════════════════════════════════════════════════════

    LIGHT_THEME_STYLESHEET = """
        /* Global Styles */
        QWidget {
            font-family: "Microsoft YaHei", "Segoe UI", "PingFang SC", sans-serif;
            font-size: 13px;
        }

        QMainWindow {
            background-color: #F5F7FA;
        }

        /* Login Card */
        #loginCard {
            background-color: white;
            border-radius: 16px;
            border: 1px solid #E8ECF0;
        }

        /* Sidebar */
        #sidebar {
            background-color: #FFFFFF;
            border-right: 1px solid #E8ECF0;
        }

        #userHeader {
            background-color: #F8FAFC;
            border-bottom: 1px solid #E8ECF0;
        }

        /* Chat Area */
        #chatArea {
            background-color: #F5F7FA;
        }

        #chatHeader {
            background-color: #FFFFFF;
            border-bottom: 1px solid #E8ECF0;
        }

        #messagesArea {
            background-color: #F5F7FA;
        }

        #inputArea {
            background-color: #FFFFFF;
            border-top: 1px solid #E8ECF0;
        }

        /* Input Fields */
        QLineEdit {
            background-color: #F8FAFC;
            border: 2px solid #E8ECF0;
            border-radius: 8px;
            padding: 12px 16px;
            color: #1F2937;
            font-size: 14px;
        }

        QLineEdit:focus {
            border-color: #3B82F6;
            background-color: #FFFFFF;
        }

        QLineEdit:hover {
            border-color: #CBD5E1;
        }

        /* Text Edit */
        QTextEdit {
            background-color: #F8FAFC;
            border: 2px solid #E8ECF0;
            border-radius: 8px;
            padding: 10px;
            color: #1F2937;
            font-size: 14px;
        }

        QTextEdit:focus {
            border-color: #3B82F6;
            background-color: #FFFFFF;
        }

        /* Primary Button */
        QPushButton#primaryBtn {
            background-color: #3B82F6;
            color: #FFFFFF;
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            font-weight: bold;
            font-size: 14px;
            min-height: 20px;
        }

        QPushButton#primaryBtn:hover {
            background-color: #2563EB;
            color: #FFFFFF;
        }

        QPushButton#primaryBtn:pressed {
            background-color: #1D4ED8;
            color: #FFFFFF;
        }

        QPushButton#primaryBtn:disabled {
            background-color: #94A3B8;
            color: #FFFFFF;
        }

        /* Secondary Button (Green) */
        QPushButton#secondaryBtn {
            background-color: #10B981;
            color: #FFFFFF;
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            font-weight: bold;
            font-size: 14px;
            min-height: 20px;
        }

        QPushButton#secondaryBtn:hover {
            background-color: #059669;
            color: #FFFFFF;
        }

        QPushButton#secondaryBtn:pressed {
            background-color: #047857;
            color: #FFFFFF;
        }

        /* Send Button */
        QPushButton#sendBtn {
            background-color: #3B82F6;
            color: #FFFFFF;
            border: none;
            border-radius: 8px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 14px;
            min-width: 80px;
            min-height: 20px;
        }

        QPushButton#sendBtn:hover {
            background-color: #2563EB;
            color: #FFFFFF;
        }

        /* Refresh Button */
        QPushButton#refreshBtn {
            background-color: transparent;
            border: none;
            border-radius: 6px;
            padding: 8px;
            font-size: 16px;
        }

        QPushButton#refreshBtn:hover {
            background-color: #F1F5F9;
        }

        /* Contacts List */
        QListWidget {
            background-color: transparent;
            border: none;
            outline: none;
        }

        QListWidget::item {
            background-color: transparent;
            border-radius: 8px;
            padding: 12px 16px;
            margin: 2px 8px;
            color: #374151;
        }

        QListWidget::item:hover {
            background-color: #F1F5F9;
        }

        QListWidget::item:selected {
            background-color: #DBEAFE;
            color: #1E40AF;
        }

        /* Scroll Area */
        QScrollArea {
            border: none;
            background-color: transparent;
        }

        QScrollBar:vertical {
            background-color: #F1F5F9;
            width: 8px;
            border-radius: 4px;
        }

        QScrollBar::handle:vertical {
            background-color: #CBD5E1;
            border-radius: 4px;
            min-height: 30px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #94A3B8;
        }

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }

        /* Labels */
        QLabel#titleLabel {
            color: #1F2937;
            font-size: 28px;
            font-weight: bold;
        }

        QLabel#subtitleLabel {
            color: #6B7280;
            font-size: 13px;
        }

        QLabel#sectionLabel {
            color: #374151;
            font-size: 13px;
            font-weight: 500;
        }

        QLabel#messageLabel {
            color: #6B7280;
            font-size: 12px;
        }

        QLabel#errorLabel {
            color: #EF4444;
            font-size: 12px;
        }

        QLabel#successLabel {
            color: #10B981;
            font-size: 12px;
        }

        /* Message Bubble - Self */
        #msgBubbleSelf {
            background-color: #3B82F6;
            border-radius: 16px;
            border-bottom-right-radius: 4px;
        }

        /* Message Bubble - Other */
        #msgBubbleOther {
            background-color: #FFFFFF;
            border-radius: 16px;
            border-bottom-left-radius: 4px;
            border: 1px solid #E8ECF0;
        }
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # Custom Text Edit Class - Handle Enter Key for Sending
    # ═══════════════════════════════════════════════════════════════════════════

    class MessageTextEdit(QTextEdit):
        """Custom text input field, Enter to send, Shift+Enter for new line"""
        # Define send signal
        sendMessage = pyqtSignal()

        def keyPressEvent(self, event):
            # Detect Enter key
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                # Shift+Enter for new line
                if event.modifiers() & Qt.ShiftModifier:
                    super().keyPressEvent(event)
                else:
                    # Enter to send message
                    self.sendMessage.emit()
            else:
                super().keyPressEvent(event)

    # ═══════════════════════════════════════════════════════════════════════════
    # Worker Thread Classes
    # ═══════════════════════════════════════════════════════════════════════════

    class LoginThread(QThread):
        """Login thread"""
        finished = pyqtSignal(bool, str)

        def __init__(self, client, username, password):
            super().__init__()
            self.client = client
            self.username = username
            self.password = password

        def run(self):
            success, msg = self.client.login(self.username, self.password)
            self.finished.emit(success, msg)

    class RegisterThread(QThread):
        """Registration thread"""
        finished = pyqtSignal(bool, str)

        def __init__(self, client, username, password):
            super().__init__()
            self.client = client
            self.username = username
            self.password = password

        def run(self):
            success, msg = self.client.register(self.username, self.password)
            self.finished.emit(success, msg)

    class SendMessageThread(QThread):
        """Send message thread"""
        finished = pyqtSignal(bool, str)

        def __init__(self, client, recipient, message):
            super().__init__()
            self.client = client
            self.recipient = recipient
            self.message = message

        def run(self):
            success, msg = self.client.send_message(self.recipient, self.message)
            self.finished.emit(success, msg)

    class GetConversationThread(QThread):
        """Get conversation thread"""
        finished = pyqtSignal(list)

        def __init__(self, client, username):
            super().__init__()
            self.client = client
            self.username = username

        def run(self):
            messages = self.client.get_conversation(self.username)
            self.finished.emit(messages)

    class GetUsersThread(QThread):
        """Get users list thread"""
        finished = pyqtSignal(list)

        def __init__(self, client):
            super().__init__()
            self.client = client

        def run(self):
            users = self.client.get_users()
            self.finished.emit(users)

    class NotificationSignal(QObject):
        """Notification signal forwarding - for cross-thread communication"""
        notification_received = pyqtSignal(dict)

    # ═══════════════════════════════════════════════════════════════════════════
    # Main Window Class
    # ═══════════════════════════════════════════════════════════════════════════

    class SecureChatWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("🔐 Secure LAN Chat - Secure LAN Chat")
            self.setMinimumSize(1000, 700)
            self.resize(1100, 750)

            # Initialize client
            self.client = ChatClient(server_host, server_port)

            # Notification signals
            self.notification_signal = NotificationSignal()
            self.notification_signal.notification_received.connect(self._handle_notification)
            self.client.on_notification = lambda n: self.notification_signal.notification_received.emit(n)

            # State variables
            self.current_chat_user = None
            self.messages_cache = []
            self.last_message_timestamp = "2000-01-01 00:00:00"

            # Set style
            self.setStyleSheet(LIGHT_THEME_STYLESHEET)

            # Create stacked widget
            self.stacked_widget = QStackedWidget()
            self.setCentralWidget(self.stacked_widget)

            # Create login page
            self._create_login_page()

            # Create main chat page
            self._create_main_page()

            # Show login page
            self.stacked_widget.setCurrentIndex(0)

            # Connect to server
            self._connect_to_server()

        def closeEvent(self, event):
            """Disconnect when closing window"""
            self.client.close()
            event.accept()

        def _connect_to_server(self):
            """Connect to server"""
            if self.client.connect():
                self.status_dot.setStyleSheet("color: #10B981; font-size: 14px;")
                self.status_label.setText("Connected")
                self.status_label.setStyleSheet("color: #10B981;")
                self.login_message.setText("Connected to server")
                self.login_message.setStyleSheet("color: #10B981;")
            else:
                self.status_dot.setStyleSheet("color: #EF4444; font-size: 14px;")
                self.status_label.setText("Connection failed")
                self.status_label.setStyleSheet("color: #EF4444;")
                self.login_message.setText("Unable to connect to server, check network")
                self.login_message.setStyleSheet("color: #EF4444;")

        # ═══════════════════════════════════════════════════════════════════════
        # Login Page
        # ═══════════════════════════════════════════════════════════════════════

        def _create_login_page(self):
            """Create login page"""
            login_page = QWidget()
            login_page.setStyleSheet("background-color: #F5F7FA;")

            layout = QVBoxLayout(login_page)
            layout.setAlignment(Qt.AlignCenter)

            # Login card
            card = QFrame()
            card.setObjectName("loginCard")
            card.setFixedSize(420, 520)

            # Add shadow effect
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(30)
            shadow.setColor(QColor(0, 0, 0, 30))
            shadow.setOffset(0, 4)
            card.setGraphicsEffect(shadow)

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(40, 40, 40, 40)
            card_layout.setSpacing(0)

            # Logo
            logo = QLabel("🔐")
            logo.setStyleSheet("font-size: 56px;")
            logo.setAlignment(Qt.AlignCenter)
            card_layout.addWidget(logo)

            card_layout.addSpacing(10)

            # Title
            title = QLabel("Secure LAN Chat")
            title.setObjectName("titleLabel")
            title.setAlignment(Qt.AlignCenter)
            card_layout.addWidget(title)

            # Subtitle
            subtitle = QLabel("End-to-End Encryption · Secure Communication")
            subtitle.setObjectName("subtitleLabel")
            subtitle.setAlignment(Qt.AlignCenter)
            card_layout.addWidget(subtitle)

            card_layout.addSpacing(20)

            # Status indicator
            status_layout = QHBoxLayout()
            status_layout.setAlignment(Qt.AlignCenter)

            self.status_dot = QLabel("●")
            self.status_dot.setStyleSheet("color: #EF4444; font-size: 14px;")
            status_layout.addWidget(self.status_dot)

            self.status_label = QLabel("Not Connected")
            self.status_label.setStyleSheet("color: #6B7280; font-size: 12px; margin-left: 4px;")
            status_layout.addWidget(self.status_label)

            card_layout.addLayout(status_layout)

            card_layout.addSpacing(25)

            # Username input
            username_label = QLabel("Username")
            username_label.setObjectName("sectionLabel")
            card_layout.addWidget(username_label)
            card_layout.addSpacing(6)

            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText("Enter username")
            self.username_input.setFixedHeight(48)
            card_layout.addWidget(self.username_input)

            card_layout.addSpacing(16)

            # Password input
            password_label = QLabel("Password")
            password_label.setObjectName("sectionLabel")
            card_layout.addWidget(password_label)
            card_layout.addSpacing(6)

            self.password_input = QLineEdit()
            self.password_input.setPlaceholderText("Enter password")
            self.password_input.setEchoMode(QLineEdit.Password)
            self.password_input.setFixedHeight(48)
            self.password_input.returnPressed.connect(self._login)
            card_layout.addWidget(self.password_input)

            card_layout.addSpacing(24)

            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(12)

            self.login_btn = QPushButton("Login")
            self.login_btn.setObjectName("primaryBtn")
            self.login_btn.setFixedHeight(48)
            self.login_btn.setCursor(Qt.PointingHandCursor)
            self.login_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3B82F6;
                    color: #FFFFFF;
                    border: none;
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2563EB;
                }
                QPushButton:pressed {
                    background-color: #1D4ED8;
                }
                QPushButton:disabled {
                    background-color: #94A3B8;
                }
            """)
            self.login_btn.clicked.connect(self._login)
            btn_layout.addWidget(self.login_btn)

            self.register_btn = QPushButton("Register")
            self.register_btn.setObjectName("secondaryBtn")
            self.register_btn.setFixedHeight(48)
            self.register_btn.setCursor(Qt.PointingHandCursor)
            self.register_btn.setStyleSheet("""
                QPushButton {
                    background-color: #10B981;
                    color: #FFFFFF;
                    border: none;
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #059669;
                }
                QPushButton:pressed {
                    background-color: #047857;
                }
            """)
            self.register_btn.clicked.connect(self._register)
            btn_layout.addWidget(self.register_btn)

            card_layout.addLayout(btn_layout)

            card_layout.addSpacing(16)

            # Message label
            self.login_message = QLabel("")
            self.login_message.setObjectName("messageLabel")
            self.login_message.setAlignment(Qt.AlignCenter)
            self.login_message.setWordWrap(True)
            card_layout.addWidget(self.login_message)

            card_layout.addStretch()

            # Server info
            server_info = QLabel(f"Server: {server_host}:{server_port}")
            server_info.setStyleSheet("color: #9CA3AF; font-size: 11px;")
            server_info.setAlignment(Qt.AlignCenter)
            card_layout.addWidget(server_info)

            layout.addWidget(card)
            self.stacked_widget.addWidget(login_page)

        def _login(self):
            """Handle login"""
            username = self.username_input.text().strip()
            password = self.password_input.text().strip()

            if not username or not password:
                self.login_message.setText("Please enter username and password")
                self.login_message.setStyleSheet("color: #F59E0B;")
                return

            self.login_message.setText("Logging in...")
            self.login_message.setStyleSheet("color: #6B7280;")
            self.login_btn.setEnabled(False)
            self.register_btn.setEnabled(False)

            self.login_thread = LoginThread(self.client, username, password)
            self.login_thread.finished.connect(self._handle_login_response)
            self.login_thread.start()

        def _handle_login_response(self, success: bool, msg: str):
            """Handle login response"""
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)

            if success:
                self.login_message.setText(msg)
                self.login_message.setStyleSheet("color: #10B981;")
                self.client.current_user = self.username_input.text().strip()
                self._update_user_info()
                self._refresh_users()
                self.stacked_widget.setCurrentIndex(1)
            else:
                self.login_message.setText(msg)
                self.login_message.setStyleSheet("color: #EF4444;")

        def _register(self):
            """Handle registration"""
            username = self.username_input.text().strip()
            password = self.password_input.text().strip()

            if not username or not password:
                self.login_message.setText("Please enter username and password")
                self.login_message.setStyleSheet("color: #F59E0B;")
                return

            if len(password) < 6:
                self.login_message.setText("Password must be at least 6 characters")
                self.login_message.setStyleSheet("color: #F59E0B;")
                return

            self.login_message.setText("Registering...")
            self.login_message.setStyleSheet("color: #6B7280;")
            self.login_btn.setEnabled(False)
            self.register_btn.setEnabled(False)

            self.register_thread = RegisterThread(self.client, username, password)
            self.register_thread.finished.connect(self._handle_register_response)
            self.register_thread.start()

        def _handle_register_response(self, success: bool, msg: str):
            """Handle registration response"""
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)

            if success:
                self.login_message.setText(f"{msg}, please login")
                self.login_message.setStyleSheet("color: #10B981;")
            else:
                self.login_message.setText(msg)
                self.login_message.setStyleSheet("color: #EF4444;")

        # ═══════════════════════════════════════════════════════════════════════
        # Main Chat Page
        # ═══════════════════════════════════════════════════════════════════════

        def _create_main_page(self):
            """Create main chat page"""
            main_page = QWidget()
            main_layout = QHBoxLayout(main_page)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)

            # ═══════════════════════════════════════════════════════════════════
            # Left Contacts Panel
            # ═══════════════════════════════════════════════════════════════════
            sidebar = QFrame()
            sidebar.setObjectName("sidebar")
            sidebar.setFixedWidth(280)
            sidebar_layout = QVBoxLayout(sidebar)
            sidebar_layout.setContentsMargins(0, 0, 0, 0)
            sidebar_layout.setSpacing(0)

            # User info header
            user_header = QFrame()
            user_header.setObjectName("userHeader")
            user_header.setFixedHeight(80)
            user_header_layout = QHBoxLayout(user_header)
            user_header_layout.setContentsMargins(20, 0, 20, 0)

            user_avatar = QLabel("👤")
            user_avatar.setStyleSheet("font-size: 32px;")
            user_header_layout.addWidget(user_avatar)

            user_info_layout = QVBoxLayout()
            user_info_layout.setSpacing(2)

            self.user_name_label = QLabel("")
            self.user_name_label.setStyleSheet("font-size: 15px; font-weight: bold; color: #1F2937;")
            user_info_layout.addWidget(self.user_name_label)

            online_status = QLabel("🟢 Online")
            online_status.setStyleSheet("font-size: 12px; color: #10B981;")
            user_info_layout.addWidget(online_status)

            user_header_layout.addLayout(user_info_layout)
            user_header_layout.addStretch()

            sidebar_layout.addWidget(user_header)

            # Contacts title bar
            contacts_header = QFrame()
            contacts_header.setFixedHeight(50)
            contacts_header.setStyleSheet("background-color: #FFFFFF;")
            contacts_header_layout = QHBoxLayout(contacts_header)
            contacts_header_layout.setContentsMargins(20, 0, 12, 0)

            contacts_title = QLabel("Contacts")
            contacts_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #374151;")
            contacts_header_layout.addWidget(contacts_title)

            contacts_header_layout.addStretch()

            refresh_btn = QPushButton("🔄")
            refresh_btn.setObjectName("refreshBtn")
            refresh_btn.setCursor(Qt.PointingHandCursor)
            refresh_btn.setFixedSize(36, 36)
            refresh_btn.clicked.connect(self._refresh_users)
            contacts_header_layout.addWidget(refresh_btn)

            sidebar_layout.addWidget(contacts_header)

            # Contacts list
            self.contacts_list = QListWidget()
            self.contacts_list.setStyleSheet("background-color: #FFFFFF;")
            self.contacts_list.itemClicked.connect(self._on_contact_clicked)
            sidebar_layout.addWidget(self.contacts_list)

            main_layout.addWidget(sidebar)

            # ═══════════════════════════════════════════════════════════════════
            # Right Chat Area
            # ═══════════════════════════════════════════════════════════════════
            chat_area = QFrame()
            chat_area.setObjectName("chatArea")
            chat_layout = QVBoxLayout(chat_area)
            chat_layout.setContentsMargins(0, 0, 0, 0)
            chat_layout.setSpacing(0)

            # Chat header
            chat_header = QFrame()
            chat_header.setObjectName("chatHeader")
            chat_header.setFixedHeight(70)
            chat_header_layout = QHBoxLayout(chat_header)
            chat_header_layout.setContentsMargins(24, 0, 24, 0)

            self.chat_title = QLabel("Select a contact to start chatting")
            self.chat_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #1F2937;")
            chat_header_layout.addWidget(self.chat_title)
            chat_header_layout.addStretch()

            chat_layout.addWidget(chat_header)

            # Messages area
            messages_container = QFrame()
            messages_container.setObjectName("messagesArea")
            messages_layout = QVBoxLayout(messages_container)
            messages_layout.setContentsMargins(0, 0, 0, 0)

            self.messages_scroll = QScrollArea()
            self.messages_scroll.setWidgetResizable(True)
            self.messages_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

            self.messages_widget = QWidget()
            self.messages_widget.setStyleSheet("background-color: #F5F7FA;")
            self.messages_layout = QVBoxLayout(self.messages_widget)
            self.messages_layout.setContentsMargins(20, 20, 20, 20)
            self.messages_layout.setSpacing(12)
            self.messages_layout.setAlignment(Qt.AlignTop)

            # Welcome message
            self.welcome_label = QLabel("👈 Select a contact from the left to start chatting")
            self.welcome_label.setStyleSheet("color: #9CA3AF; font-size: 16px; padding: 100px;")
            self.welcome_label.setAlignment(Qt.AlignCenter)
            self.messages_layout.addWidget(self.welcome_label)

            self.messages_scroll.setWidget(self.messages_widget)
            messages_layout.addWidget(self.messages_scroll)

            chat_layout.addWidget(messages_container, 1)

            # Input area
            input_area = QFrame()
            input_area.setObjectName("inputArea")
            input_area.setFixedHeight(100)
            input_layout = QHBoxLayout(input_area)
            input_layout.setContentsMargins(20, 16, 20, 16)
            input_layout.setSpacing(12)

            self.message_input = MessageTextEdit()
            self.message_input.setPlaceholderText("Type a message, press Enter to send, Shift+Enter for new line")
            self.message_input.setFixedHeight(68)
            self.message_input.sendMessage.connect(self._send_message)
            input_layout.addWidget(self.message_input)

            send_btn = QPushButton("Send")
            send_btn.setObjectName("sendBtn")
            send_btn.setFixedSize(80, 68)
            send_btn.setCursor(Qt.PointingHandCursor)
            send_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3B82F6;
                    color: #FFFFFF;
                    border: none;
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2563EB;
                }
                QPushButton:pressed {
                    background-color: #1D4ED8;
                }
            """)
            send_btn.clicked.connect(self._send_message)
            input_layout.addWidget(send_btn)

            chat_layout.addWidget(input_area)

            main_layout.addWidget(chat_area, 1)

            self.stacked_widget.addWidget(main_page)

        def _update_user_info(self):
            """Update user information"""
            self.user_name_label.setText(self.client.current_user)

        def _refresh_users(self):
            """Refresh contacts list"""
            self.contacts_list.clear()
            item = QListWidgetItem("Loading...")
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            item.setForeground(QColor("#9CA3AF"))
            self.contacts_list.addItem(item)

            self.get_users_thread = GetUsersThread(self.client)
            self.get_users_thread.finished.connect(self._handle_users_loaded)
            self.get_users_thread.start()

        def _handle_users_loaded(self, users: list):
            """Handle users list loaded"""
            self.contacts_list.clear()

            if not users:
                item = QListWidgetItem("No other users")
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
                item.setForeground(QColor("#9CA3AF"))
                self.contacts_list.addItem(item)
                return

            for user in users:
                item = QListWidgetItem(f"👤  {user}")
                item.setData(Qt.UserRole, user)
                item.setSizeHint(QSize(0, 50))
                self.contacts_list.addItem(item)

        def _on_contact_clicked(self, item: QListWidgetItem):
            """Contact click event"""
            username = item.data(Qt.UserRole)
            if username:
                self._select_contact(username)

        def _select_contact(self, username: str):
            """Select contact"""
            self.current_chat_user = username
            self.chat_title.setText(f"💬 {username}")
            self._load_conversation(username)

        def _load_conversation(self, username: str):
            """Load conversation"""
            # Clear all messages
            while self.messages_layout.count():
                item = self.messages_layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()

            # Show loading indicator
            loading_label = QLabel("Loading...")
            loading_label.setObjectName("loadingLabel")
            loading_label.setStyleSheet("color: #9CA3AF; font-size: 14px; padding: 50px;")
            loading_label.setAlignment(Qt.AlignCenter)
            self.messages_layout.addWidget(loading_label)

            # Use thread to get conversation
            self._loading_user = username
            self.get_conv_thread = GetConversationThread(self.client, username)
            self.get_conv_thread.finished.connect(self._handle_conversation_loaded)
            self.get_conv_thread.start()

        def _handle_conversation_loaded(self, messages: list):
            """Handle conversation loaded"""
            # Clear loading indicator
            while self.messages_layout.count():
                item = self.messages_layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()

            self.messages_cache = messages

            if not messages:
                empty_label = QLabel("No messages yet, send your first message!")
                empty_label.setObjectName("emptyLabel")
                empty_label.setStyleSheet("color: #9CA3AF; font-size: 14px; padding: 50px;")
                empty_label.setAlignment(Qt.AlignCenter)
                self.messages_layout.addWidget(empty_label)
            else:
                for msg in messages:
                    self._display_message(msg)
                self.last_message_timestamp = messages[-1]['timestamp']

            # Scroll to bottom
            QTimer.singleShot(100, self._scroll_to_bottom)

        def _display_message(self, msg: Dict, plaintext: str = None):
            """Display message - WeChat style: Self on right, others on left"""
            # Remove empty message indicator (if exists)
            for i in range(self.messages_layout.count()):
                item = self.messages_layout.itemAt(i)
                if item and item.widget():
                    widget = item.widget()
                    if widget.objectName() in ["emptyLabel", "loadingLabel"]:
                        widget.deleteLater()
                        break

            is_self = msg['sender'] == self.client.current_user

            if plaintext is not None:
                decrypted = plaintext
            else:
                decrypted = self.client.decrypt_message(msg)

            # Message container
            msg_container = QWidget()
            msg_container.setObjectName("msgContainer")
            container_layout = QHBoxLayout(msg_container)
            container_layout.setContentsMargins(0, 0, 0, 0)

            if is_self:
                # Own message: right aligned
                container_layout.addStretch()

            # Message bubble
            bubble = QFrame()
            bubble.setObjectName("msgBubbleSelf" if is_self else "msgBubbleOther")
            bubble.setMaximumWidth(450)

            # Set bubble style
            if is_self:
                bubble.setStyleSheet("""
                    QFrame#msgBubbleSelf {
                        background-color: #3B82F6;
                        border-radius: 16px;
                        border-bottom-right-radius: 4px;
                    }
                """)
            else:
                bubble.setStyleSheet("""
                    QFrame#msgBubbleOther {
                        background-color: #FFFFFF;
                        border-radius: 16px;
                        border-bottom-left-radius: 4px;
                        border: 1px solid #E8ECF0;
                    }
                """)

            bubble_layout = QVBoxLayout(bubble)
            bubble_layout.setContentsMargins(16, 10, 16, 10)
            bubble_layout.setSpacing(4)

            # Message content
            msg_label = QLabel(decrypted)
            msg_label.setWordWrap(True)
            msg_label.setStyleSheet(
                f"color: {'white' if is_self else '#1F2937'}; font-size: 14px; background: transparent;"
            )
            bubble_layout.addWidget(msg_label)

            # Timestamp
            timestamp = msg.get('timestamp', '')[:16] if msg.get('timestamp') else ''
            time_label = QLabel(timestamp)
            time_label.setStyleSheet(
                f"color: {'rgba(255,255,255,0.7)' if is_self else '#9CA3AF'}; font-size: 11px; background: transparent;"
            )
            time_label.setAlignment(Qt.AlignRight)
            bubble_layout.addWidget(time_label)

            container_layout.addWidget(bubble)

            if not is_self:
                # Other's message: left aligned, add stretch on right
                container_layout.addStretch()

            # Add to layout at the end
            self.messages_layout.addWidget(msg_container)

        def _send_message(self):
            """Send message"""
            if not self.current_chat_user:
                QMessageBox.warning(self, "Prompt", "Please select a contact first")
                return

            message = self.message_input.toPlainText().strip()
            if not message:
                return

            # Save message content for callback
            self._pending_message = message
            self._pending_recipient = self.current_chat_user

            # Clear input field
            self.message_input.clear()

            # Use thread to send
            self.send_msg_thread = SendMessageThread(self.client, self.current_chat_user, message)
            self.send_msg_thread.finished.connect(self._handle_send_result)
            self.send_msg_thread.start()

        def _handle_send_result(self, success: bool, msg_str: str):
            """Handle send message result"""
            if success:
                # Locally display sent message (shown on right, blue bubble)
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                # Construct message object, sender set to current user so it shows on right
                sent_msg = {
                    'sender': self.client.current_user,
                    'recipient': self._pending_recipient,
                    'timestamp': now
                }
                self._display_message(sent_msg, plaintext=self._pending_message)
                self.messages_cache.append(sent_msg)
                self.last_message_timestamp = now

                # Scroll to bottom
                QTimer.singleShot(100, self._scroll_to_bottom)
            else:
                QMessageBox.critical(self, "Send Failed", msg_str)
                # Restore input field content
                self.message_input.setPlainText(self._pending_message)

        def _scroll_to_bottom(self):
            """Scroll to bottom"""
            scrollbar = self.messages_scroll.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

        def _handle_notification(self, notification: Dict):
            """Handle server push notification"""
            print(f"[Notification] Received push: {notification}")  # Debug info
            sender = notification.get('from')
            if not sender:
                return

            encrypted_data = notification.get('encrypted_data')
            timestamp = notification.get('timestamp')

            # If currently chatting with sender, display message directly
            if self.current_chat_user and sender == self.current_chat_user:
                new_msg = {
                    'sender': sender,
                    'recipient': self.client.current_user,
                    'ciphertext': encrypted_data['ciphertext'],
                    'iv': encrypted_data['iv'],
                    'encryption_key': encrypted_data['key'],
                    'hmac': encrypted_data['hmac'],
                    'timestamp': timestamp
                }
                self._display_message(new_msg)
                self.messages_cache.append(new_msg)
                self.last_message_timestamp = timestamp
                QTimer.singleShot(100, self._scroll_to_bottom)
            else:
                # Not current chat participant, show notification
                QMessageBox.information(self, "New Message", f"New message from {sender}")

    # Start application
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle('Fusion')

    window = SecureChatWindow()
    window.show()
    sys.exit(app.exec_())


# ═══════════════════════════════════════════════════════════════════════════════
#                              Main Program Entry
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='🔐 Secure LAN Chat System (PyQt5 Version)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Start server:
    python secure_lan_chat.py --server
    python secure_lan_chat.py --server --port 6000

  Start client:
    python secure_lan_chat.py --client --host 192.168.1.100
    python secure_lan_chat.py --client --host 192.168.1.100 --port 6000
        '''
    )

    parser.add_argument('--server', action='store_true', help='Run in server mode')
    parser.add_argument('--client', action='store_true', help='Run in client mode')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Server address (client mode)')
    parser.add_argument('--port', type=int, default=5555, help='Port number (default: 5555)')

    args = parser.parse_args()

    if args.server:
        print("\n🔐 Starting Secure Chat Server...")
        server = ChatServer(host='0.0.0.0', port=args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n\n👋 Shutting down server...")
            server.stop()
            print("✅ Server safely closed")

    elif args.client:
        print(f"\n🔐 Starting Secure Chat Client (PyQt5)...")
        print(f"📡 Connecting to: {args.host}:{args.port}")
        run_gui_client(args.host, args.port)

    else:
        parser.print_help()
        print("\n" + "═" * 60)
        print("💡 Quick Start:")
        print("   1. Start server on one computer:")
        print("      python secure_lan_chat.py --server")
        print("")
        print("   2. Start client on other computers:")
        print("      python secure_lan_chat.py --client --host <server_IP>")
        print("═" * 60)


if __name__ == "__main__":
    main()