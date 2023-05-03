import socket
import time
import secrets
import string
import ssl
from cryptography.hazmat.primitives import hashes
from struct import pack, unpack
import sys
from base64 import b16encode, b16decode

'''
Utility function to send byte stream data with length to the socket. 
Sends the length first by packing it into a 4 byte integer.
'''
def send_data_with_length(data: bytes, socket: socket.socket):
    length = len(data)
    socket.sendall(pack('>I', length))
    socket.sendall(data)

'''
Utility function to receive bytes data from the TCP stream. 
Data is accompanied by its length first.
'''
def recv_data_with_length(s: socket.socket) -> bytes:
    data_len = s.recv(4)
    data_len = unpack('>I', data_len)[0]
    data = s.recv(data_len)
    return data


def generate_random_alphanumeric_string(length: int) -> str:
    """
    Generate a random password with at least one lowercase letter,
    one uppercase letter, and one digit.
    """

    alphabet = string.ascii_letters + string.digits
    
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)):
            return password
        
    
def bytes_XOR(byte1: bytes, byte2: bytes) -> bytes:
    """
    Calculate the XOR of two byte strings.
    """
    length = max(len(byte1), len(byte2))

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')

def set_MSB(binary: str, length: int) -> str:
    if len(binary) != length:
        for i in range(length - len(binary) - 1):
            binary = "0" + binary
        binary = "1" + binary
    
    return binary
        


def generate_credentials() -> tuple:
    '''
    Generate credentials for the user.
    '''

    ID = generate_random_alphanumeric_string(10)
    PW = generate_random_alphanumeric_string(10)
    r1 = secrets.randbits(128)
    r2 = secrets.randbits(128)

    # Stripping 0b from the start
    bin_r1 = set_MSB(bin(r1)[2:], 128)
    
    bin_r2 = set_MSB(bin(r2)[2:], 128)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID.encode())
    hash.update(PW.encode())
    A = hash.finalize()

    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(bin_r1.encode())
    hash1.update(PW.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(bin_r2.encode())
    hash2.update(PW.encode())

    B = bytes_XOR(hash1.finalize(), hash2.finalize())

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(bin_r1.encode())
    hash.update(ID.encode())
    hash.update(bin_r2.encode())
    UID = hash.finalize()

    return ID, PW, A, B, UID, bin_r1, bin_r2




def main():

    if len(sys.argv) != 2:
        print("Usage: python3 user_regPhase.py <INDEX OF USER>")
        sys.exit(1)

    index = int(sys.argv[1])

    ID, PW, A, B, UID, bin_r1, bin_r2 = generate_credentials()

    # Send to the RC using TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname='127.0.0.1')
    conn.connect(('127.0.0.1', 10024))

    send_data_with_length(b'USER REG', conn)

    # Send ID to the RC to check for availability
    send_data_with_length(UID, conn)

    # Receive confirmation of ID availability from RC
    confirmation = recv_data_with_length(conn).decode()


    if confirmation == 'UID NOT AVAILABLE':

        while True:
            ID, PW, A, B, UID, bin_r1, bin_r2 = generate_credentials()
            send_data_with_length(UID, conn)

            confirmation = recv_data_with_length(conn).decode()

            if confirmation == 'UID AVAILABLE':
                break

    send_data_with_length(A, conn)

    with open(f'credentials{index}.txt', 'w') as f:
        f.write(f'ID,{ID}\n')
        f.write(f"PW,{PW}\n")
        f.write(f"r1,{int(bin_r1, 2)}\n")
        f.write(f"r2,{int(bin_r2, 2)}\n")


    # Receive C and D from the RC
    C = recv_data_with_length(conn)
    D = recv_data_with_length(conn)

    # Receive ListSj from RC
    ListSj = recv_data_with_length(conn)

    W = bytes_XOR((bin_r1 + bin_r2).encode(), A)
    
    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(bin_r2.encode())
    hash1.update(ID.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(bin_r1.encode())
    hash2.update(PW.encode())

    X = bytes_XOR(hash1.finalize(), hash2.finalize())
    X = bytes_XOR(X, C)

    Y = bytes_XOR(B, D)

    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(bin_r1.encode())
    hash1.update(ID.encode())
    hash1.update(PW.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(ID.encode())
    hash2.update(PW.encode())
    hash2.update(bin_r2.encode())

    Z = bytes_XOR(hash1.finalize(), hash2.finalize())
    Z = bytes_XOR(Z, ListSj)

    USK = bytes_XOR(A, D)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(PW.encode())
    hash.update(USK)
    E = hash.finalize()


    with open(f"Smart Card {index}.txt", "w") as f:
        W_hex = b16encode(W).decode("utf-8")
        f.write(f"W,{W_hex}\n")
        X_hex = b16encode(X).decode("utf-8")
        f.write(f"X,{X_hex}\n")
        Y_hex = b16encode(Y).decode("utf-8")
        f.write(f"Y,{Y_hex}\n")
        Z_hex = b16encode(Z).decode("utf-8")
        f.write(f"Z,{Z_hex}\n")
        E_hex = b16encode(E).decode("utf-8")
        f.write(f"E,{E_hex}\n")




if __name__ == '__main__':
    main()
