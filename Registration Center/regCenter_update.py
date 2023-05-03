import socket
import time
import secrets
import ssl
from struct import pack, unpack
from cryptography.hazmat.primitives import hashes
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
    length = len(byte1)

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')


def handle_client(conn: socket.socket):
    entity = recv_data_with_length(conn)

    if entity == b'USER UPDATE':
        handle_user_update(conn)

    if entity == b"SERVER UPDATE":
        handle_server_update(conn)




def handle_user_update(conn: socket.socket):

    UID = recv_data_with_length(conn)
    tau = recv_data_with_length(conn)
    timestamp = float(recv_data_with_length(conn).decode())

    timestamp2 = time.time()
    if timestamp2 - timestamp > DELTA_T:
        print("User timed out.")
        send_data_with_length(b'TIMEOUT ERROR', conn)
        conn.close()
        return
    else:
        send_data_with_length(b'200 OK', conn)

    # Check if UID is in the file
    flag = 0
    with open(f"users.txt", "r") as f:
        f.readline()
        for line in f:
            line = line[:-1]
            UID_val, C = line.split(",")
            if UID_val == b16encode(UID).decode():
                flag = 1
                break

    if flag == 0:
        send_data_with_length("404 ERROR: User not found")
        conn.close()
        return

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(b16decode(C.encode()))
    hash.update(str(timestamp).encode())
    hash.update(UID)

    tau_prime = hash.finalize()

    if tau_prime != tau:
        send_data_with_length("403 ERROR: Incorrect credentials")
        conn.close()
        return
    
    # If yes, send the list of servers to the user
    with open("servers.txt", "r") as f:
        ListSj = f.read()

    send_data_with_length(ListSj.encode(), conn)
    conn.close()

    print("Update successful.")


def handle_server_update(conn: socket.socket):
    ID = recv_data_with_length(conn)
    omega = recv_data_with_length(conn)
    timestamp = float(recv_data_with_length(conn).decode())

    timestamp2 = time.time()
    if timestamp2 - timestamp > DELTA_T:
        print("Server timed out.")
        send_data_with_length(b'TIMEOUT ERROR', conn)
        conn.close()
        return

    flag = 0
    with open("servers.txt", "r") as f:
        f.readline()
        for line in f:
            line = line[:-1]
            ID_val= line.split(",")[0]
            Q = line.split(",")[1]
            SSK = line.split(",")[2]
            if ID_val == ID.decode():
                flag = 1
                break

    if flag == 0:
        send_data_with_length(b"404 ERROR: Server not found", conn)
        conn.close()
        return
    
    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(b16decode(Q.encode()))
    hash.update(str(timestamp).encode())
    hash.update(b16decode(SSK.encode()))
    omega_prime = hash.finalize()

    if omega_prime != omega:
        send_data_with_length(b"403 ERROR: Incorrect credentials", conn)
        conn.close()
        return
    
    # If yes, send the list of servers to the user
    with open("users.txt", "r") as f:
        ListUsers = f.read()
    
    send_data_with_length(ListUsers.encode(), conn)
    conn.close()

    print("Update successful.")


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 10025))
    s.listen(1)

    try:
        while True:

            # Wait for a connection
            conn, fromaddr = s.accept()
            handle_client(conn)
    finally:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        s.close()


DELTA_T = 1

if __name__ == '__main__':
    main()