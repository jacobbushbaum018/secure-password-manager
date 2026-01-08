import random
import string
import pyperclip
import json
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class PasswordVault:
    """Encrypted password storage vault."""
    
    def __init__(self, vault_path="password_vault.enc"):
        self.vault_path = Path(vault_path)
        self.salt_path = Path(vault_path + ".salt")
        self.cipher = None
        
    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def _initialize_vault(self, master_password: str) -> bytes:
        """Create new vault with random salt."""
        salt = random.randbytes(16)
        self.salt_path.write_bytes(salt)
        return salt
    
    def unlock(self, master_password: str) -> bool:
        """Unlock the vault with master password."""
        try:
            # Load or create salt
            if self.salt_path.exists():
                salt = self.salt_path.read_bytes()
            else:
                salt = self._initialize_vault(master_password)
            
            # Derive key and create cipher
            key = self._derive_key(master_password, salt)
            self.cipher = Fernet(key)
            
            # Test decryption if vault exists
            if self.vault_path.exists():
                self._load_vault()
            
            return True
        except Exception as e:
            print(f"Failed to unlock vault: {e}")
            return False
    
    def _load_vault(self) -> dict:
        """Load and decrypt vault contents."""
        if not self.vault_path.exists():
            return {}
        
        encrypted_data = self.vault_path.read_bytes()
        decrypted_data = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def _save_vault(self, data: dict):
        """Encrypt and save vault contents."""
        json_data = json.dumps(data, indent=2).encode()
        encrypted_data = self.cipher.encrypt(json_data)
        self.vault_path.write_bytes(encrypted_data)
    
    def store_password(self, service: str, username: str, password: str):
        """Store a password entry in the vault."""
        if not self.cipher:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        
        vault_data = self._load_vault()
        
        if service not in vault_data:
            vault_data[service] = []
        
        vault_data[service].append({
            "username": username,
            "password": password
        })
        
        self._save_vault(vault_data)
        print(f"✓ Password stored for {username}@{service}")
    
    def retrieve_password(self, service: str, username: str = None) -> list:
        """Retrieve password(s) for a service."""
        if not self.cipher:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        
        vault_data = self._load_vault()
        
        if service not in vault_data:
            return []
        
        entries = vault_data[service]
        if username:
            entries = [e for e in entries if e["username"] == username]
        
        return entries
    
    def list_services(self) -> list:
        """List all stored services."""
        if not self.cipher:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        
        vault_data = self._load_vault()
        return list(vault_data.keys())
    
    def delete_password(self, service: str, username: str = None):
        """Delete password entry."""
        if not self.cipher:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        
        vault_data = self._load_vault()
        
        if service not in vault_data:
            print(f"Service '{service}' not found.")
            return
        
        if username:
            vault_data[service] = [e for e in vault_data[service] if e["username"] != username]
            if not vault_data[service]:
                del vault_data[service]
            print(f"✓ Deleted {username}@{service}")
        else:
            del vault_data[service]
            print(f"✓ Deleted all entries for {service}")
        
        self._save_vault(vault_data)


def generate_password(length=12, include_uppercase=True, include_numbers=True, 
                     include_special_characters=True):
    """
    Generates a secure password.

    Parameters:
        length (int): Length of the password.
        include_uppercase (bool): Include uppercase letters.
        include_numbers (bool): Include numbers.
        include_special_characters (bool): Include special characters.

    Returns:
        str: The generated password.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters for security.")

    # Character pools
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase if include_uppercase else ""
    digits = string.digits if include_numbers else ""
    specials = string.punctuation if include_special_characters else ""

    # Ensure at least one character from each enabled set is included
    all_chars = lower + upper + digits + specials
    if not all_chars:
        raise ValueError("At least one character set must be enabled.")

    # Generate the password - ensure at least one from each category
    password = [random.choice(lower)]
    if include_uppercase:
        password.append(random.choice(upper))
    if include_numbers:
        password.append(random.choice(digits))
    if include_special_characters:
        password.append(random.choice(specials))

    # Fill the rest of the password length with random choices from all_chars
    password += random.choices(all_chars, k=length - len(password))

    # Shuffle the password to ensure randomness
    random.shuffle(password)
    return ''.join(password)


def main():
    print("=" * 50)
    print("    SECURE PASSWORD MANAGER")
    print("=" * 50)
    
    vault = PasswordVault()
    
    # Unlock vault
    print("\n[Master Password Required]")
    master_password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock(master_password):
        print("Failed to unlock vault. Exiting.")
        return
    
    print("✓ Vault unlocked successfully!\n")
    
    while True:
        print("\n" + "=" * 50)
        print("OPTIONS:")
        print("  1. Generate and store new password")
        print("  2. Retrieve stored password")
        print("  3. List all services")
        print("  4. Delete password")
        print("  5. Exit")
        print("=" * 50)
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == "1":
            # Generate new password
            print("\n--- Password Generation ---")
            service = input("Service name (e.g., gmail, github): ").strip()
            username = input("Username/email: ").strip()
            
            try:
                length = int(input("Password length (default 16): ") or 16)
                include_uppercase = input("Include uppercase? (Y/n): ").lower() != "n"
                include_numbers = input("Include numbers? (Y/n): ").lower() != "n"
                include_special_characters = input("Include special chars? (Y/n): ").lower() != "n"

                password = generate_password(
                    length=length,
                    include_uppercase=include_uppercase,
                    include_numbers=include_numbers,
                    include_special_characters=include_special_characters,
                )
                
                print(f"\n✓ Generated Password: {password}")
                pyperclip.copy(password)
                print("✓ Copied to clipboard!")
                
                save = input("\nSave to vault? (Y/n): ").lower() != "n"
                if save:
                    vault.store_password(service, username, password)
                
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            # Retrieve password
            print("\n--- Retrieve Password ---")
            service = input("Service name: ").strip()
            username = input("Username (optional, press Enter to see all): ").strip() or None
            
            entries = vault.retrieve_password(service, username)
            
            if not entries:
                print(f"No passwords found for '{service}'")
            else:
                print(f"\nFound {len(entries)} entry/entries:")
                for i, entry in enumerate(entries, 1):
                    print(f"\n  [{i}] Username: {entry['username']}")
                    print(f"      Password: {entry['password']}")
                
                copy_choice = input("\nCopy a password to clipboard? (enter number or n): ").strip()
                if copy_choice.isdigit() and 1 <= int(copy_choice) <= len(entries):
                    pyperclip.copy(entries[int(copy_choice) - 1]["password"])
                    print("✓ Copied to clipboard!")
        
        elif choice == "3":
            # List services
            services = vault.list_services()
            if not services:
                print("\nVault is empty.")
            else:
                print(f"\nStored services ({len(services)}):")
                for service in sorted(services):
                    entries = vault.retrieve_password(service)
                    print(f"  • {service} ({len(entries)} account(s))")
        
        elif choice == "4":
            # Delete password
            print("\n--- Delete Password ---")
            service = input("Service name: ").strip()
            username = input("Username (optional, press Enter to delete all): ").strip() or None
            
            confirm = input(f"Confirm deletion? (yes/n): ").lower()
            if confirm == "yes":
                vault.delete_password(service, username)
        
        elif choice == "5":
            print("\nClosing vault. Goodbye!")
            break
        
        else:
            print("Invalid option. Please select 1-5.")


if __name__ == "__main__":
    main()