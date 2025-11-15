import socket
import sys
import os
import pickle
from dotenv import load_dotenv

try:
    from DES_Chat import des_encrypt, des_decrypt, bits_to_hex, hex_to_bits
    from RSA_KeyExchange import RSA
except ImportError as e:
    print(f"Error: Required module not found - {e}")
    sys.exit(1)

try:
    load_dotenv()
except:
    pass

LHOST = os.getenv("LHOST", "127.0.0.1")
RHOST = os.getenv("RHOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8080))


def sender_mode_with_rsa():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"\n[SENDER] Attempting to connect to {RHOST}:{PORT}...")
            s.connect((RHOST, PORT))
            print("[SENDER] Connection successful!")
            s.settimeout(None)
            
            print("\n" + "=" * 70)
            print("STEP 1: RSA KEY EXCHANGE")
            print("=" * 70)
            
            print("\n[SENDER] Waiting for receiver's RSA public key...")
            receiver_public_data = s.recv(8192)
            receiver_public_key = pickle.loads(receiver_public_data)
            
            print(f"[SENDER] Received receiver's RSA public key:")
            print(f"  e = {receiver_public_key[0]}")
            print(f"  n = {receiver_public_key[1]}")
            
            import random
            import string
            des_key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            print(f"\n[SENDER] Generated DES key: '{des_key}'")
            
            print("[SENDER] Encrypting DES key with receiver's RSA public key...")
            
            des_key_int = int.from_bytes(des_key.encode(), 'big')
            
            e, n = receiver_public_key
            encrypted_key = pow(des_key_int, e, n)
            
            print(f"[SENDER] Encrypted DES key: {encrypted_key}")
            
            print("[SENDER] Sending encrypted DES key to receiver...")
            s.sendall(pickle.dumps(encrypted_key))
            
            confirmation = s.recv(1024).decode('utf-8')
            if confirmation == "KEY_RECEIVED":
                print("[SENDER] Receiver confirmed key receipt.")
            
            print("\n" + "=" * 70)
            print("STEP 2: SEND ENCRYPTED MESSAGE")
            print("=" * 70)
            
            plaintext = input("\n[SENDER] Enter your message: ")
            
            print("[SENDER] Encrypting message with DES...")
            encrypted_bits = des_encrypt(plaintext, des_key)
            encrypted_hex = bits_to_hex(encrypted_bits)
            
            print(f"[SENDER] Encrypted message (hex): {encrypted_hex}")
            
            print("[SENDER] Sending encrypted message...")
            s.sendall(encrypted_hex.encode('utf-8'))
            
            print("\n✓ Message sent successfully!")
            print("=" * 70)
            
    except socket.timeout:
        print(f"\n✗ Error: Connection timed out. Is the receiver listening on {RHOST}:{PORT}?")
    except ConnectionRefusedError:
        print(f"\n✗ Error: Connection refused. Is the receiver running on {RHOST}:{PORT}?")
    except Exception as e:
        print(f"\n✗ An error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nReturning to menu...\n")


def receiver_mode_with_rsa():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((LHOST, PORT))
            s.listen()
            
            print(f"\n[RECEIVER] Server listening on {LHOST}:{PORT}...")
            print("[RECEIVER] Waiting for connection...\n")
            
            conn, addr = s.accept()
            
            with conn:
                print(f"[RECEIVER] Connected by {addr}")
                
                print("\n" + "=" * 70)
                print("STEP 1: RSA KEY EXCHANGE")
                print("=" * 70)
                
                print("\n[RECEIVER] Generating RSA key pair...")
                rsa = RSA(key_size=512)
                public_key = rsa.get_public_key()
                
                print(f"[RECEIVER] Generated RSA key pair:")
                print(f"  Public key (e): {public_key[0]}")
                print(f"  Public key (n): {public_key[1]}")
                print(f"  Private key: RAHASIA")
                
                print("\n[RECEIVER] Sending RSA public key to sender...")
                conn.sendall(pickle.dumps(public_key))
                
                print("[RECEIVER] Waiting for encrypted DES key...")
                encrypted_key_data = conn.recv(8192)
                encrypted_key = pickle.loads(encrypted_key_data)
                
                print(f"[RECEIVER] Received encrypted DES key: {encrypted_key}")
                
                print("[RECEIVER] Decrypting DES key with RSA private key...")
                des_key_int = rsa.decrypt(encrypted_key)
                
                byte_length = (des_key_int.bit_length() + 7) // 8
                des_key_bytes = des_key_int.to_bytes(byte_length, 'big')
                des_key = des_key_bytes.decode('utf-8')
                
                print(f"[RECEIVER] Decrypted DES key: '{des_key}'")
                
                conn.sendall("KEY_RECEIVED".encode('utf-8'))
                
                print("\n" + "=" * 70)
                print("STEP 2: RECEIVE ENCRYPTED MESSAGE")
                print("=" * 70)
                
                print("\n[RECEIVER] Waiting for encrypted message...")
                data = conn.recv(8192)
                
                if data:
                    encrypted_hex = data.decode('utf-8').strip()
                    print(f"[RECEIVER] Received encrypted message (hex): {encrypted_hex}")
                    
                    try:
                        print("[RECEIVER] Decrypting message with DES...")
                        encrypted_bits = hex_to_bits(encrypted_hex)
                        decrypted_text = des_decrypt(encrypted_bits, des_key)
                        
                        print(f"\n✓ Decrypted message: '{decrypted_text}'")
                        
                    except Exception as e:
                        print(f"\n✗ Error decrypting message: {e}")
                        print(f"Raw data: {encrypted_hex}")
                else:
                    print("[RECEIVER] No data received.")
                
                print("=" * 70)
    
    except OSError as e:
        if e.errno == 98 or e.errno == 10048:
            print(f"\n✗ Error: Address {LHOST}:{PORT} is already in use.")
        else:
            print(f"\n✗ An error occurred: {e}")
    except Exception as e:
        print(f"\n✗ An error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nReturning to menu...\n")


def main():
    print("=" * 70)
    print("SECURE CHAT WITH RSA KEY EXCHANGE")
    print("=" * 70)
    print("\nThis application uses RSA to securely exchange a DES key")
    print("and then uses DES encryption for secure communication.")
    print("\nNo pre-shared key required!")
    
    while True:
        print("\n" + "=" * 70)
        print("Choose your role:")
        print("=" * 70)
        print("1. Sender   (Initiate connection and send message)")
        print("2. Receiver (Wait for connection and receive message)")
        print("3. Quit")
        print("=" * 70)
        
        choice = input("\nEnter choice (1, 2, or 3): ").strip()
        
        if choice == '1':
            sender_mode_with_rsa()
        elif choice == '2':
            receiver_mode_with_rsa()
        elif choice == '3':
            print("\nExiting chat. Goodbye!")
            break
        else:
            print("\n✗ Invalid input. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
