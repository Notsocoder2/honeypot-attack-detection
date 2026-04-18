import socket
import time
from datetime import datetime
import threading


ip_attempts = {}
#blocked IPS
blocked_ips = {}

username_attempts = {}
global_attempts = []

#logging function
def log_attempt(ip,username,password):
    timestamp= datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"[{timestamp}] IP={ip} USER={username} PASS={password}\n" 
    with open("logs/log.txt", "a") as f:
        f.write(log_entry)





def handle_client(client, addr):
    
    ip = addr[0]

    current_time = time.time()

    if ip in blocked_ips:
        block_time = blocked_ips[ip]

        if current_time - block_time < 60:
            print(f"[BLOCKED] {ip} still in cooldown")
            client.close()
            return
        else:
            print(f"[UNBLOCKED] {ip} allowed again")
            del blocked_ips[ip]

    print(f"connected : {ip}")

    try:
        global global_attempts
        #send fake login attempts
        client.send("welcome to Server\n".encode())
        client.send("Username: ".encode())

        #receive username
        username = client.recv(1024).decode().strip()

        client.send("Password: ".encode())

        password = client.recv(1024).decode().strip()

        #skip attempt if username or password EMPTY
        if not username or not password:
            client.close()
            return 

        #logging the attempt
        log_attempt(ip, username, password)

        #update attempt
        current_time= time.time()
        if ip not  in ip_attempts:
            ip_attempts[ip] = []

        ip_attempts[ip].append(current_time)

        # time based Detection
        ip_attempts[ip]=[
            t for t in ip_attempts[ip]
            if current_time-t< 15
        ]
            
        

        if len(ip_attempts[ip]) >8:
            print(f"[ALERT][IP] brute force detected from {ip}")
            blocked_ips[ip] = current_time

        #username based detection
        if username not in username_attempts:
            username_attempts[username] = []
        
        username_attempts[username].append(current_time)
         
        username_attempts[username] = [
            t for t in username_attempts[username]
            if current_time - t<20

        ]
        if len(username_attempts[username]) > 5:
            print(f"[ALERT][USERNAME] attack detected on '{username}'")

        #global tracking
        global_attempts.append(current_time)
        global_attempts = [
            t for t in global_attempts
            if current_time - t < 10
        ]
        if len(global_attempts) >15:
            print("[ALERT][GLOBAL] high traffic detected")

        #server response
        client.send("Login failed\n".encode())

        print(f"[LOGGED] {ip} -> {username}:{password}")

    except Exception as e:
        print("Error:", e)

    finally:
        client.close()


#create server
server = socket.socket()
server.bind(("127.0.0.1", 12348))
server.listen(5)

print("server running....... waiting for connection")

while True:
    client, addr=server.accept()

    thread = threading.Thread(target=handle_client, args=(client, addr))
    thread.start()