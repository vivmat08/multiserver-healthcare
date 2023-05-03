import socket
import ssl
import string
import secrets
from cryptography.hazmat.primitives import hashes
from struct import pack, unpack
import sys
from base64 import b16encode

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
        
    
def generate_credentials() -> tuple:
    '''
    Generate credentials for the server.
    '''

    ID = generate_random_alphanumeric_string(10)
    PW = generate_random_alphanumeric_string(10)
    r_s = secrets.randbits(10 * 8)

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID.encode())
    hash.update(str(r_s).encode())
    hash.update(PW.encode())
    P = hash.finalize()

    hash = hashes.Hash(hashes.SHA3_256())
    hash.update(ID.encode())
    hash.update(PW.encode())
    Q = hash.finalize()
    Q = bytes_XOR(P, Q)

    return ID, PW, P, Q, r_s



def bytes_XOR(byte1: bytes, byte2: bytes) -> bytes:
    """
    Calculate the XOR of two byte strings.
    """
    length = len(byte1)

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')


def main():

    if len(sys.argv) != 2:
        print("Usage: python3 server_regPhase.py <INDEX OF SERVER>")
        sys.exit(1)

    index = int(sys.argv[1])

    ID, PW, P, Q, r_s = generate_credentials()

    # Send to the RC using TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname='127.0.0.1')
    conn.connect(('127.0.0.1', 10024))

    send_data_with_length(b'SERVER REG', conn)


    # Send ID to the RC to check for availability
    send_data_with_length(ID.encode(), conn)

    # Receive confirmation of ID availability from RC
    confirmation = recv_data_with_length(conn).decode()


    if confirmation == 'ID NOT AVAILABLE':

        while True:
            ID, PW, P, Q, r_s = generate_credentials()
            send_data_with_length(ID.encode(), conn)

            confirmation = recv_data_with_length(conn).decode()

            if confirmation == 'ID AVAILABLE':
                break


    send_data_with_length(P, conn)
    send_data_with_length(Q, conn)
    send_data_with_length(b'Goa', conn)

    ADDRESS = "127.0.0.1"
    PORT = str(10000 + index)
    send_data_with_length(ADDRESS.encode(), conn)
    send_data_with_length(PORT.encode(), conn)

    # Store the credentials in a file
    with open(f'credentials{index}.txt', 'w') as f:
        f.write("ID," + ID + '\n')
        f.write("PW," + PW + '\n')
        f.write("P," + b16encode(P).decode() + '\n')

    
    # Receive the SSK from the RC
    SSK = recv_data_with_length(conn)
    SSK = b16encode(SSK).decode()

    #receive ListUID and ListC from RC
    List = recv_data_with_length(conn).decode()

    with open(f'users{index}.txt', 'w') as f:
        f.write(List)

    # Store the SSK in the credentials file
    with open(f'credentials{index}.txt', 'a') as f:
        f.write("SS," + SSK + '\n')
        f.write("Loc,Goa\n")

    conn.close()



if __name__ == "__main__":
    main()

