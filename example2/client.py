import socket
import random

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 5000))

    try:
        # İsteği olustur
        data = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n" + \
            "A" * 1000
        #data = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n" + \
        #    " ".join([str(random.randint(33, 126)) for _ in range(7)]) + \
        #    " 100 " + \
        #    " ".join([str(random.randint(33, 126)) for _ in range(4)])

        data = "".join([str(c) for c in data if str(c).isascii()])

        s.sendall(data.encode())

        # serverın yanıtını al
        response = s.recv(1024)
        print(response.decode())
    except ConnectionResetError:
        print("Sunucu bağlantıyı kapattı.")

    # Bağlantıyı kapat
    s.close()

if __name__ == "__main__":
    main()
