import socket
import ssl
import string
import secrets
from cryptography.hazmat.primitives import hashes
from struct import pack, unpack
import sys
from base64 import b16encode, b16decode
import threading
import time

'''
Utility function to send byte stream data with length to the socket. 
Sends the length first by packing it into a 4 byte integer.
'''
def send_data_with_length(data: bytes, socket: socket.socket):
    try:
        length = len(data)
        socket.sendall(pack('>I', length))
        socket.sendall(data)
    except:
        socket.close()

'''
Receive bytes data from the TCP stream. Data is accompanied
by its length first.
'''
def recv_data_with_length(socket: socket.socket) -> bytes:
    try:
        data_len = socket.recv(4)
        data_len = unpack('>I', data_len)[0]
        data = socket.recv(data_len)
        return data
    except:
        socket.close()

def bytes_XOR(byte1: bytes, byte2: bytes) -> bytes:
    """
    Calculate the XOR of two byte strings.
    """
    length = max(len(byte1), len(byte2))

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')


def handle_client(conn: socket.socket, index: int):
    alpha = recv_data_with_length(conn)
    beta = recv_data_with_length(conn)
    timestamp = recv_data_with_length(conn)
    timestamp_float = float(timestamp.decode())

    timestamp2 = time.time()
    if timestamp2 - timestamp_float > DELTA_T:
        print("Client timed out")
        send_data_with_length(b"TIMEOUT ERROR", conn)
        conn.close()
        return
    
    else:
        send_data_with_length(b"200 OK", conn)
    
    hash = hashes.Hash(hashes.SHA3_256())
    with open(f"credentials{index}.txt", "r") as f:
        ID = f.readline()[:-1].split(",")[1]
        f.readline()
        f.readline()
        SSK = b16decode(f.readline()[:-1].split(",")[1].encode())
        Loc = f.readline()[:-1].split(",")[1]

    hash.update(ID.encode())
    hash.update(SSK)
    hash.update(timestamp)
    UID = bytes_XOR(hash.finalize(), alpha)

    # Looking for C of client wtih UID given
    flag = 0
    with open(f"users{index}.txt", "r") as f:
        f.readline()
        for line in f:
            line = line[:-1]
            UID_val, C = line.split(",")
            if UID_val == b16encode(UID).decode():
                flag = 1
                break

    if flag == 0:
        send_data_with_length(b"404 ERROR: User not found", conn)
        conn.close()
        return

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(SSK)
    hash.update(b16decode(C.encode()))
    hash.update(timestamp)

    beta_prime = hash.finalize()

    if beta_prime != beta:
        send_data_with_length(b"403 ERROR: Incorrect credentials", conn)
        conn.close()
        return
    
    # Generate gamma
    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(b16decode(C.encode()))
    hash.update(UID)
    hash.update(ID.encode())
    hash.update(beta)

    gamma = bytes_XOR(hash.finalize(), (str(VALIDITY_TIME) + "," + Loc).encode())

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(str(VALIDITY_TIME).encode())
    hash.update(b16decode(C.encode()))
    hash.update(str(timestamp2 - timestamp_float).encode())
    sigma = hash.finalize()

    send_data_with_length(gamma, conn)
    send_data_with_length(sigma, conn)
    send_data_with_length(str(timestamp2).encode(), conn)


    response = recv_data_with_length(conn)
    if response == b'TIMEOUT ERROR':
        conn.close()
        return
    
    # Validity of sigma
    response = recv_data_with_length(conn)
    if response != b'200 OK':
        conn.close()
        return
    
    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(ID.encode())
    hash.update(b16decode(C.encode()))
    hash.update(Loc.encode())
    hash.update(str(VALIDITY_TIME).encode())

    SK = hash.finalize()
    SK_hex = b16encode(SK).decode()
    print(f"Session key = {SK_hex}\n")
    print(f"Active for f{VALIDITY_TIME} seconds.\n")


def server_update(index: int):

    print("Enter ID")
    ID = input()
    print("Enter password")
    PW = input()

    with open(f"credentials{index}.txt", "r") as f:
        f.readline()
        f.readline()
        P = f.readline()[:-1].split(",")[1]
        SSK = f.readline()[:-1].split(",")[1]
    
    P = b16decode(P.encode())
    SSK = b16decode(SSK.encode())

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID.encode())
    hash.update(PW.encode())
    Q = bytes_XOR(hash.finalize(), P)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(Q)
    timestamp = time.time()
    hash.update(str(timestamp).encode())
    hash.update(SSK)
    omega = hash.finalize()


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 10025))

    send_data_with_length(b"SERVER UPDATE", s)

    send_data_with_length(ID.encode(), s)
    send_data_with_length(omega, s)
    send_data_with_length(str(timestamp).encode(), s)


    ListClients = recv_data_with_length(s)
    if ListClients == b"TIMEOUT ERROR":
        print("Server timed out")
        s.close()
        exit()
    
    if ListClients == b"404 ERROR: Server not found":
        print(ListClients.decode())
        s.close()
        exit()
    
    if ListClients == b"403 ERROR: Incorrect credentials":
        print(ListClients.decode())
        s.close()
        exit()
    
    with open(f"users{index}.txt", "w") as f:
        f.write(ListClients.decode())





def main():

    if len(sys.argv) != 2:
        print("Usage: python3 server_regPhase.py <INDEX OF SERVER>")
        sys.exit(1)

    index = int(sys.argv[1])

    server_update(index)

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = ('localhost', 10000 + index)
    print('Starting server...')
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('Waiting for a connection...')
            connection, client_address = sock.accept()
            
            # Create a thread to handle this request
            t1 = threading.Thread(target= handle_client, args=(connection, index))
            t1.start()
        
    finally:
        sock.close()
        connection.close()





DELTA_T = 1
VALIDITY_TIME = 600 # 10 minutes


if __name__ == "__main__":
    main()