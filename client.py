import socket
import random

usernames = ["admin", "root", "user",  "guest","test" ,"dhruv99999"]

passwords = ["123456", "password", "admin123", "letmein", "welcome","password5665","mutthmaare"]
client = socket.socket()
#connect to server
client.connect(("127.0.0.1", 12348))

#receive message
print(client.recv(1024).decode())
#send username
username = random.choice(usernames)
client.send((username + "\n").encode())
#receive password prompt
print(client.recv(1024).decode())
#send password
password = random.choice(passwords)
client.send((password + "\n").encode())

#receive server response
print(client.recv(1024).decode())

client.close()
