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


def handle_client(conn: socket.socket, KEY: int):
    entity = recv_data_with_length(conn).decode()

    if entity == 'SERVER REG':
        handle_server_reg(conn, KEY)

    if entity == 'USER REG':
        handle_user_reg(conn, KEY)


    
def handle_server_reg(conn: socket.socket, KEY: int):

    while True:
        ID = recv_data_with_length(conn).decode()

        # Check if ID is already in use
        with open("servers.txt", "r") as f:
            for line in f:
                if ID in line:
                    send_data_with_length(b'ID NOT AVAILABLE', conn)
                    continue
        
        send_data_with_length(b'ID AVAILABLE', conn)
        break

    # If not, generate credentials and send them to the server
    P = recv_data_with_length(conn)
    Q = recv_data_with_length(conn)
    loc = recv_data_with_length(conn)

    address = recv_data_with_length(conn).decode()
    port = recv_data_with_length(conn).decode()


    timestamp = time.time()
    timestamp_bytes = bytes(str(timestamp), 'utf-8')
    
    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(int.to_bytes(KEY, 32, 'big'))
    hash.update(P)
    hash.update(timestamp_bytes)
    SSK = hash.finalize()
    send_data_with_length(SSK, conn)

    Q = b16encode(Q).decode()
    SSK = b16encode(SSK).decode()

    #sending ListUID and ListC to server
    with open("users.txt", "r") as f:
        send_data_with_length(bytes(f.read(), 'utf-8'), conn)

    # Write the server's credentials to the file
    with open("servers.txt", "a") as f:
        f.write(ID + "," + Q + "," + SSK + "," + loc.decode() + "," + address + "," + port + "\n")


def handle_user_reg(conn: socket.socket, KEY: int):

    while True:
        UID = recv_data_with_length(conn)
        UID_hex = b16encode(UID).decode("utf-8")

        # Check if UID is already in use
        with open("users.txt", "r") as f:
            for line in f:
                UID_val, C_val = line.split(",")
                if UID_hex == UID_val:
                    send_data_with_length(b'UID NOT AVAILABLE', conn)
                    continue
        
        send_data_with_length(b'UID AVAILABLE', conn)
        break

    # If not, generate credentials and send them to the user
    A = recv_data_with_length(conn)


    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(UID)
    hash.update(int.to_bytes(KEY, 32, 'big'))
    r3 = secrets.randbits(256)
    hash.update(int.to_bytes(r3, 32, 'big'))
    USK = hash.finalize()


    hash1 = hashes.Hash(hashes.SHA3_256())
    hash1.update(int.to_bytes(KEY, 32, 'big'))
    hash1.update(int.to_bytes(r3, 32, 'big'))
    hash1.update(A)

    hash2 = hashes.Hash(hashes.SHA3_256())
    hash2.update(UID)
    hash2.update(A)
    
    C = bytes_XOR(hash1.finalize(), hash2.finalize())
    C = bytes_XOR(C, USK)

    D = bytes_XOR(USK, A)

    with open("users.txt", "a") as f:
        f.write(UID_hex + "," + b16encode(C).decode() + "\n")

    send_data_with_length(C, conn)
    send_data_with_length(D, conn)

    # making list of Sj
    ListSj = ""
    with open("servers.txt", "r") as f:
        ListSj = f.read()
    
    send_data_with_length(bytes(ListSj, 'utf-8'), conn) 



def main():

    KEY = secrets.randbits(256)

    with open("servers.txt", "w") as f:
        f.write("ID,Q,SSK,Loc,Address,Port\n")

    with open("users.txt", "w") as f:
        f.write("UID,C\n")


    # Create a SSL Socket
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile="certificate.pem", keyfile="key.pem")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 10024))
    s.listen(1)


    try:
        while True:

            # Wait for a connection
            newsocket, fromaddr = s.accept()
            conn = context.wrap_socket(newsocket, server_side=True)
            handle_client(conn, KEY)
    finally:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        s.close()


DELTA_T = 1

if __name__ == '__main__':
    main()