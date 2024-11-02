import base64
import json
import logging
import os
import secrets
import string
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManagerError(Exception):
    """Base exception class for Password Manager"""
    def __init__(self, message="A password manager error occurred"):
        self.message = message
        super().__init__(self.message)

class SecurityError(PasswordManagerError):
    """Security related errors"""
    def __init__(self, message="A security error occurred"):
        super().__init__(message)

class ValidationError(PasswordManagerError):
    """Input validation errors"""
    def __init__(self, message="Invalid input provided"):
        super().__init__(message)

class PasswordManager:
    """Secure password manager with encryption and validation"""
    
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 64
    MIN_MASTER_PASSWORD_LENGTH = 12
    SALT_LENGTH = 16
    ITERATION_COUNT = 100_000
    
    def __init__(self, data_dir: Union[str, Path] = None):
        """Initialize the password manager"""
        self.data_dir = Path(data_dir) if data_dir else Path.home() / '.password_manager'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.data_dir / 'master.key'
        self.salt_file = self.data_dir / 'salt'
        self.passwords_file = self.data_dir / 'passwords.enc'
        
        # Configure logging
        self._setup_logging()
        
        # Initialize encryption
        self.cipher_suite = None
    
    def _setup_logging(self):
        """Configure logging with proper format and handling"""
        log_file = self.data_dir / 'password_manager.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('PasswordManager')

    def initialize(self, master_password: str) -> None:
        """Initialize the password manager with a master password"""
        if not self._validate_master_password(master_password):
            raise ValidationError(
                f"Master password must be at least {self.MIN_MASTER_PASSWORD_LENGTH} characters long "
                "and contain uppercase, lowercase, numbers, and special characters"
            )
        
        # Generate new salt and key
        salt = self._generate_salt()
        key = self._generate_key(master_password, salt)
        
        # Save salt and encrypted master key
        self._save_salt(salt)
        self._save_key(key)
        
        self.cipher_suite = Fernet(key)
        self.logger.info("Password manager initialized successfully")

    def unlock(self, master_password: str) -> bool:
        """Unlock the password manager with master password"""
        try:
            salt = self._load_salt()
            key = self._generate_key(master_password, salt)
            self.cipher_suite = Fernet(key)
            
            # Verify by trying to load passwords
            self.load_passwords()
            self.logger.info("Password manager unlocked successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unlock password manager: {str(e)}")
            raise SecurityError("Invalid master password or corrupted data")

    def add_password(self, service: str, username: str, password: str) -> None:
        """Add or update password for a service"""
        if not self.cipher_suite:
            raise SecurityError("Password manager is locked")
            
        self._validate_service_name(service)
        self._validate_username(username)
        self._validate_password(password)
        
        passwords = self.load_passwords()
        
        # Encrypt password
        encrypted_password = self._encrypt(password)
        
        # Store password with metadata
        passwords[service] = {
            "username": username,
            "password": encrypted_password,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        self._save_passwords(passwords)
        self.logger.info(f"Password added/updated for service: {service}")

    def retrieve_password(self, service: str) -> Optional[Dict]:
        """Retrieve password information for a service"""
        if not self.cipher_suite:
            raise SecurityError("Password manager is locked")
            
        passwords = self.load_passwords()
        
        if service not in passwords:
            self.logger.warning(f"Password not found for service: {service}")
            return None
            
        entry = passwords[service]
        decrypted_password = self._decrypt(entry["password"])
        
        return {
            "username": entry["username"],
            "password": decrypted_password,
            "created_at": entry["created_at"],
            "updated_at": entry["updated_at"]
        }

    def generate_password(self, length: int = 16) -> str:
        """Generate a secure random password"""
        if not (self.MIN_PASSWORD_LENGTH <= length <= self.MAX_PASSWORD_LENGTH):
            raise ValidationError(
                f"Password length must be between {self.MIN_PASSWORD_LENGTH} "
                f"and {self.MAX_PASSWORD_LENGTH}"
            )
            
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest with random characters
        all_characters = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_characters))
            
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def load_passwords(self) -> Dict:
        """Load encrypted passwords from file"""
        if not self.cipher_suite:
            raise SecurityError("Password manager is locked")
            
        if not self.passwords_file.exists():
            return {}
            
        try:
            encrypted_data = self.passwords_file.read_bytes()
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data)
            
        except Exception as e:
            self.logger.error(f"Failed to load passwords: {str(e)}")
            raise SecurityError("Failed to decrypt passwords")

    def _save_passwords(self, passwords: Dict) -> None:
        """Save encrypted passwords to file"""
        try:
            encrypted_data = self.cipher_suite.encrypt(
                json.dumps(passwords).encode()
            )
            self.passwords_file.write_bytes(encrypted_data)
            
        except Exception as e:
            self.logger.error(f"Failed to save passwords: {str(e)}")
            raise SecurityError("Failed to encrypt and save passwords")

    def _generate_salt(self) -> bytes:
        """Generate a random salt"""
        return os.urandom(self.SALT_LENGTH)

    def _generate_key(self, master_password: str, salt: bytes) -> bytes:
        """Generate encryption key from master password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATION_COUNT,
        )
        return base64.urlsafe_b64encode(
            kdf.derive(master_password.encode())
        )

    def _save_salt(self, salt: bytes) -> None:
        """Save salt to file"""
        self.salt_file.write_bytes(salt)

    def _load_salt(self) -> bytes:
        """Load salt from file"""
        if not self.salt_file.exists():
            raise SecurityError("Salt file not found")
        return self.salt_file.read_bytes()

    def _save_key(self, key: bytes) -> None:
        """Save encryption key to file"""
        self.key_file.write_bytes(key)

    def _encrypt(self, data: str) -> str:
        """Encrypt a string"""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def _decrypt(self, encrypted_data: str) -> str:
        """Decrypt a string"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def _validate_master_password(password: str) -> bool:
        """Validate master password strength"""
        if len(password) < PasswordManager.MIN_MASTER_PASSWORD_LENGTH:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        return all([has_upper, has_lower, has_digit, has_special])

    @staticmethod
    def _validate_service_name(service: str) -> None:
        """Validate service name"""
        if not service or len(service) > 64 or not service.strip():
            raise ValidationError("Invalid service name")

    @staticmethod
    def _validate_username(username: str) -> None:
        """Validate username"""
        if not username or len(username) > 128 or not username.strip():
            raise ValidationError("Invalid username")

    @staticmethod
    def _validate_password(password: str) -> None:
        """Validate password"""
        if not password or len(password) < PasswordManager.MIN_PASSWORD_LENGTH:
            raise ValidationError(
                f"Password must be at least {PasswordManager.MIN_PASSWORD_LENGTH} characters long"
            )

def main():
    """Main program loop"""
    pm = PasswordManager()
    
    try:
        # First-time setup or unlock existing
        if not pm.key_file.exists():
            print("First-time setup. Please create a master password.")
            while True:
                master_password = input("Enter master password: ")
                if pm._validate_master_password(master_password):
                    pm.initialize(master_password)
                    break
                print("Password too weak. Please try again.")
        else:
            while True:
                master_password = input("Enter master password to unlock: ")
                try:
                    if pm.unlock(master_password):
                        break
                except SecurityError:
                    print("Invalid master password. Please try again.")

        while True:
            print("\nPassword Manager")
            print("1. Add password")
            print("2. Retrieve password")
            print("3. Generate secure password")
            print("4. Exit")
            
            try:
                choice = input("Enter your choice: ")
                
                if choice == "1":
                    service = input("Enter the service name: ")
                    username = input("Enter the username: ")
                    use_generated = input("Generate secure password? (y/n): ").lower()
                    
                    if use_generated == 'y':
                        length = int(input("Enter desired password length: "))
                        password = pm.generate_password(length)
                        print(f"Generated password: {password}")
                    else:
                        password = input("Enter the password: ")
                        
                    pm.add_password(service, username, password)
                    print(f"Password for {service} added successfully!")
                    
                elif choice == "2":
                    service = input("Enter the service name: ")
                    result = pm.retrieve_password(service)
                    
                    if result:
                        print(f"\nService: {service}")
                        print(f"Username: {result['username']}")
                        print(f"Password: {result['password']}")
                        print(f"Created: {result['created_at']}")
                        print(f"Last updated: {result['updated_at']}")
                    else:
                        print("Service not found.")
                        
                elif choice == "3":
                    length = int(input("Enter desired password length: "))
                    print("Generated password:", pm.generate_password(length))
                    
                elif choice == "4":
                    print("Goodbye!")
                    break
                    
                else:
                    print("Invalid choice. Try again.")
                    
            except ValidationError as e:
                print(f"Validation error: {str(e)}")
            except SecurityError as e:
                print(f"Security error: {str(e)}")
            except ValueError as e:
                print(f"Invalid input: {str(e)}")
            except Exception as e:
                print(f"An error occurred: {str(e)}")
                
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Clean up resources if needed
        pass

if __name__ == "__main__":
    main()