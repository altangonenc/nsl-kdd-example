import socket
import mariadb
import os

def main():
    db_host = os.environ.get("DB_HOST", "localhost")
    db_user = os.environ.get("DB_USER", "admin")
    db_password = os.environ.get("DB_PASSWORD", "adminadmin")
    db_name = os.environ.get("DB_NAME", "testdb")

    host = "0.0.0.0"
    port = 5001
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Server is running.")

    while True:
        conn, addr = server_socket.accept()

        print("Connection accepted:", addr)
        data = conn.recv(1024)
        request = data.decode()

        # Extract username and password from the request
        username = request.split("\r\n")[0].split("?")[1].split("&")[0].split("=")[1]
        password = request.split("\r\n")[0].split("?")[1].split("&")[1].split("=")[1]

        # Save the username and password to the sql database
        save_to_database(username, password, db_host, db_user, db_password, db_name)

        response_data = "Received your request. Thanks!"
        conn.sendall(response_data.encode())

        conn.close()

def save_to_database(username, password, db_host, db_user, db_password, db_name):
    try:
        conn = mariadb.connect(
            user=db_user,
            password=db_password,
            host=db_host,
            port=3306,
            database=db_name
        )
        cur = conn.cursor()
        cur.execute("INSERT INTO user_table (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        print("Username and password saved to the database.")
    except mariadb.Error as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
