import socket
import time
import secrets
import string
import ssl
from cryptography.hazmat.primitives import hashes
from struct import pack, unpack
import sys
from base64 import b16decode, b16encode

'''
Utility function to send byte stream data with length to the socket. 
Sends the length first by packing it into a 4 byte integer.
'''
def send_data_with_length(data: bytes, socket: socket.socket):
    length = len(data)
    socket.sendall(pack('>I', length))
    socket.sendall(data)

'''
Receive bytes data from the TCP stream. Data is accompanied
by its length first.
'''
def recv_data_with_length(s: socket.socket) -> bytes:
    data_len = s.recv(4)
    data_len = unpack('>I', data_len)[0]
    data = s.recv(data_len)
    return data


def bytes_XOR(byte1: bytes, byte2: bytes) -> bytes:
    """
    Calculate the XOR of two byte strings.
    """
    length = max(len(byte1), len(byte2))

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')


def smart_card_update(ID: str, PW: str, index: int, r1: str, r2: str, X: bytes, Z: bytes, UID: bytes):
    
    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(r2.encode())
    hash1.update(ID.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(r1.encode())
    hash2.update(PW.encode())

    C = bytes_XOR(hash1.finalize(), hash2.finalize())
    C = bytes_XOR(C, X)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(C)
    timestamp = time.time()
    hash.update(str(timestamp).encode())
    hash.update(UID)
    tau = hash.finalize()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(("localhost", 10025))

    send_data_with_length(b"USER UPDATE", conn)

    send_data_with_length(UID, conn)
    send_data_with_length(tau, conn)
    send_data_with_length(str(timestamp).encode(), conn)

    response = recv_data_with_length(conn).decode()
    if response != "200 OK":
        print(response)
        print("Update failed.")
        conn.close()
        return
    
    ListSj = recv_data_with_length(conn)
    if ListSj == b"404 ERROR: User not found":
        print(ListSj.decode())
        print("Update failed.")
        conn.close()
        exit()

    if ListSj == b"403 ERROR: Incorrect credentials":
        print(ListSj.decode())
        print("Update failed.")
        conn.close()
        exit()

    conn.close()

    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(r1.encode())
    hash1.update(ID.encode())
    hash1.update(PW.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(ID.encode())
    hash2.update(PW.encode())
    hash2.update(r2.encode())

    Z = bytes_XOR(hash1.finalize(), hash2.finalize())
    Z = bytes_XOR(Z, ListSj)

    Z_hex = b16encode(Z).decode()
    
    f = open(f"Smart Card {index}.txt", "r")
    smart_card = ""
    smart_card += f.readline() + f.readline() + f.readline()
    f.readline()
    smart_card += f"Z,{Z_hex}\n"
    smart_card += f.readline()
    f.close()

    f1 = open(f"Smart Card {index}.txt", "w")
    f1.write(smart_card)
    f1.close()

    print("Update successful.")




def main():
    if len(sys.argv) != 2:
        print("Usage: python3 user_service.py <INDEX OF USER>")
        sys.exit(1)

    index = int(sys.argv[1])


    print("Enter ID ")
    ID = input()
 
    print("Enter password")
    PW = input()

    cred = dict()
    with open(f"Smart Card {index}.txt", "r") as f:
        W = b16decode(f.readline()[:-1].split(",")[1].encode())
        X = b16decode(f.readline()[:-1].split(",")[1].encode())
        Y = b16decode(f.readline()[:-1].split(",")[1].encode())
        Z = b16decode(f.readline()[:-1].split(",")[1].encode())
        E = f.readline()[:-1].split(",")[1]


    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID.encode())
    hash.update(PW.encode())

    try:
        r1_r2 = bytes_XOR(W, hash.finalize())
        r1_r2 = r1_r2.decode("utf-8")
        r1 = r1_r2[:128]
        r2 = r1_r2[128:]
    except:
        print("Invalid username or password.")
        exit()

    with open(f"credentials{index}.txt", "r") as f:
        f.readline()
        f.readline()
        r1_file = f.readline()[:-1].split(",")[1]
        r2_file = f.readline()[:-1].split(",")[1]

    try:
        assert(int(r1_file) == int(r1, 2))
        assert(int(r2_file) == int(r2, 2))
    except:
        print("Wrong username or password.")
        exit()

    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(r1.encode())
    hash1.update(PW.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(r2.encode())
    hash2.update(PW.encode())

    B = bytes_XOR(hash1.finalize(), hash2.finalize())

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID.encode())
    hash.update(PW.encode())
    USK = bytes_XOR(hash.finalize(), B)
    USK = bytes_XOR(USK, Y)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(r1.encode())
    hash.update(ID.encode())
    hash.update(r2.encode())
    UID = hash.finalize()

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(PW.encode())
    hash.update(USK)
    E_dash = hash.finalize()
    E_prime = b16encode(E_dash).decode()
    
    try:
        assert(E == E_prime)
    except:
        print("Wrong username or password.")
        exit()

    smart_card_update(ID, PW, index, r1, r2, X, Z, UID)

    with open(f"Smart Card {index}.txt", "r") as f:
        W = b16decode(f.readline()[:-1].split(",")[1].encode())
        X = b16decode(f.readline()[:-1].split(",")[1].encode())
        Y = b16decode(f.readline()[:-1].split(",")[1].encode())
        Z = b16decode(f.readline()[:-1].split(",")[1].encode())
        E = f.readline()[:-1].split(",")[1]

    # STEP 2
    # Calculating ListSj
    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(ID.encode())
    hash1.update(PW.encode())
    hash1.update(r2.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(r1.encode())
    hash2.update(ID.encode())
    hash2.update(PW.encode())

    ListSj = bytes_XOR(hash1.finalize(), hash2.finalize())
    ListSj = bytes_XOR(ListSj, Z)
    ListSj = ListSj.decode("utf-8")

    # Choosing server n
    print("Which server to request from? (1, 2,...)")
    n = int(input())
    ListSj = ListSj.split("\n")[n]
    SSK = b16decode(ListSj.split(",")[2].encode())
    ID_server = ListSj.split(",")[0]
    address = ListSj.split(",")[-2]
    port = int(ListSj.split(",")[-1])

    # Send to the server 3
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((address, port))

    # Alpha
    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID_server.encode())
    hash.update(SSK)
    timestamp = time.time()
    hash.update(str(timestamp).encode())
    alpha = bytes_XOR(hash.finalize(), UID)

    # Sending alpha
    send_data_with_length(alpha, conn)

    # C
    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(r1.encode())
    hash1.update(PW.encode())

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(r2.encode())
    hash2.update(ID.encode())

    C = bytes_XOR(hash1.finalize(), hash2.finalize())
    C = bytes_XOR(C, X)

    # Beta
    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(SSK)
    hash.update(C)
    hash.update(str(timestamp).encode())
    beta = hash.finalize()

    # Sending beta
    send_data_with_length(beta, conn)

    # Sending time
    send_data_with_length(str(timestamp).encode(), conn)

    # Server response
    response = recv_data_with_length(conn).decode()
    if response != "200 OK":
        print(response)
        conn.close()
        exit()

    gamma = recv_data_with_length(conn)
    if gamma == b"404 ERROR: User not found":
        print(gamma.decode())
        conn.close()
        exit()

    if gamma == b"403 ERROR: Incorrect credentials":
        print(gamma.decode())
        conn.close()
        exit()

    sigma = recv_data_with_length(conn)
    timestamp2 = recv_data_with_length(conn).decode()

    timestamp3 = time.time()
    if timestamp3 - float(timestamp2) > DELTA_T:
        print("Connection timeout.")
        send_data_with_length(b"TIMEOUT ERROR", conn)
        conn.close()
        exit()

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(C)
    hash.update(UID)
    hash.update(ID_server.encode())
    hash.update(beta)
    VT_Loc = bytes_XOR(hash.finalize(), gamma).decode()

    VT = VT_Loc.split(",")[0]
    Loc = VT_Loc.split(",")[1]
    VT = VT[25:]
    VT = int(VT)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(str(VT).encode())
    hash.update(C)
    hash.update(str(float(timestamp2) - timestamp).encode())
    sigma_prime = hash.finalize()

    if sigma != sigma_prime:
        print("403 ERROR: Incorrect credentials")
        send_data_with_length(b"403 ERROR: Incorrect credentials", conn)
        conn.close()
        exit()
    else:
        send_data_with_length(b"200 OK", conn)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(ID_server.encode())
    hash.update(C)
    hash.update(Loc.encode())
    hash.update(str(VT).encode())

    SK = hash.finalize()
    SK_hex = b16encode(SK).decode()
    print(f"Session Key = {SK_hex}\n")
    print(f"Active for {VT} seconds.\n")
    
    conn.close()


DELTA_T = 1

if __name__ == '__main__':
    main()