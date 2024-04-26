import socket, sys, threading, rsa


''' [DESCRIPTION]
    The Program is TCP Based Chat Application, meaning there is a server that listens for incoming connections and a client that connects to the server.
    Unlike a UDP based chat application, TCP is connection oriented, meaning that a connection is established between the client and server before data is sent.
    UDP is connectionless, meaning that data can be sent without establing a server handshake.
    ''''''
    ENCRYPTION IS RSA: RSA IS ASYMMETRIC ENCRYPTION (PUBLIC/PRIVATE KEY)
    --> PUBLIC KEY IS USED TO ENCRYPT MESSAGE AND PRIVATE KEY IS USED TO DECRYPT MESSAGE
    ** THE HOSTING CLIENT WILL SEND THE PUBLIC KEY TO THE CLIENT, 
    ** THE CLIENT WILL USE THE PUBLIC KEY TO ENCRYPT THE MESSAGE AND SEND IT BACK TO THE HOSTING CLIENT
'''

''' [SETUP DIRECTIONS]
    First configure ngrok to expose your local server to the internet.
    [ngrok] takes your localhost and gives you a public URL that you can use to expose your local web server to the internet.

    (to run) *** REMEMBER TO SPECIFY TCP AND PORT NUMBER ***
    $ngrok tcp 9999
    
    Enter the ngrok URL and port in the client.py file and server.py file.
    Then run the server.py file, and the client.py file.

    ***** FOR CLIENT: USE THE FORWARDING URL FROM NGROK (NOT LOCALHOST) 
    ***** FOR SERVER: USE LOCALHOST
    ***** USE SEPERATE PORTS FOR SERVER AND CLIENT
    ***-> CLIENT SHOULD CONNECT TO SAME PORT AS NGROK PORT
'''

PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(1024)
PUBLIC_PARTNER = None

hostname = socket.gethostname()
clientList = []
usernames = []

host = "127.0.0.1"
port = 8000

# START SERVER
S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
S.bind((hostname, port))
print("[!] Server is listening on port 8000")
print("[!] PUBLIC KEY: \n" + str(PUBLIC_KEY))
print("[!] PRIVATE KEY: \n" + str(PRIVATE_KEY))
S.listen()


# stopThread = False

'''Broadcasts message to all clients in clientList'''
def broadcastHandler(message):

#    encryptedMsg = rsa.encrypt(message.encode(), PUBLIC_PARTNER)
  #  print(f"[!] [BROADCAST HANDLER] \n [ENCRYPTED MESSAGE] \n {encryptedMsg}")
    print(f"[!] [BROADCAST HANDLER] \n [MESSAGE] \n {message}")
    for client in clientList:
        client.send(message)
       # client.send(encryptedMsg)
    #encryptedMsg = None

def receiveHandler(client):
    '''Handles  and starts the main functionality of the server, checks if message is a kick or ban, and kicks or bans user accordingly.'''
    while True:
        try:

            message = client.recv(1024)
         #   encryptedMsg = rsa.decrypt(client.recv(1024), PRIVATE_KEY).decode()

            print("SENDING BROADCAST HANDLER #1")
            broadcastHandler(message)
            #broadcastHandler(encryptedMsg)

            ''' DECODES MESSAG to SEE IF KICK OR BAN IS PARSED '''
            if message.decode('ascii').startswith("KICK"):
                if usernames[clientList.index(client)] == "admin":
                    nameToKick = message.decode('ascii')[5:]
                    kickUser(nameToKick)
                    #client.send("You are admin, you cannot kick yourself.".encode('ascii'))

                    with open("kicks.txt", 'a') as f:
                        f.write(f"{nameToKick}\n")
                        nameToKick = message.decode('ascii')[5:]
                        kickUser(nameToKick)
                        print(f"[!] KICKING {nameToKick} !")
                else:
                 # client.send("You are not admin, you cannot kick users.".encode('ascii'))

                 print("SENDING BROADCAST HANDLER #2")
               #  broadcastHandler(encryptedMsg)

            elif message.decode('ascii').startswith("BAN"):
                if usernames[clientList.index(client)] == "admin":

                    nameToBan = message.decode('ascii')[4:]
                    kickUser(nameToBan)
                    print(f"[!] {nameToBan} was banned!")

                    with open("bans.txt", 'a') as f:
                        f.write(f"{nameToBan}\n")
                        nameToKick = message.decode('ascii')[4:]
                        kickUser(nameToKick)
                        print(f"[!] KICKING {nameToKick} !")

                else:
                    client.send("You are not admin, you cannot kick users.".encode('ascii'))
                    broadcastHandler(message)

            else:
                broadcastHandler(message)
                #broadcastHandler(encryptedMsg)

        except Exception as e:
            print("[ERROR] An error occurred!" + str(e))
            idx = clientList.index(client)
            clientList.remove(client)
            client.close()
            broadcastHandler(f"[!] {usernames[idx]} has left the chat!")


def checkBans():
    '''Handles the receiving of messages from the client.'''
    while True:
        global stopThread
        if stopThread:
            break

        try:
            client, address = S.accept()
           # client.send(PUBLIC_KEY.save_pkcs1("PEM"))
           # public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))  # , 'PEM')

            client.send("USER".encode('ascii'))
            username = client.recv(1024).decode('ascii')

            print(f"[!] {str(address)} has connected.")

            ## checks if username is in the banned list, if so, refuse connection.
            with open("bans.txt", 'r') as f:
                bans = f.readlines()

            if username + "\n" in bans:
                client.send("BAN".encode('ascii'))
                broadcastHandler(f"[!] {username} was banned!").encode('ascii')
                client.close()
                continue

            ## checks if username is admin, if so, ask for password.
            if username == "admin":
                client.send("PASS".encode('ascii'))
                password = client.recv(1024).decode('ascii')

                if password != "adminpass":
                    client.send("REFUSE".encode('ascii'))
                    print(f"[!] {username} has failed to connect due to incorrect password.")
                    client.send("REFUSE".encode('ascii'))
                    # clientList.remove(client)
                    client.close()
                    continue

            # if username is not in banned list, or is not admin, add username to list and client to clientList.
            usernames.append(username)
            clientList.append(client)

            print(f"[!] {username} has joined the chat!")

            broadcastHandler(f"[!] {username} has joined the chat!").encode('ascii')

            client.send("Connected to server!".encode('ascii'))
            print(f"[!] {username} has joined the chat!")

            thread = threading.Thread(target=receiveHandler, args=(client,))
            thread.start()

        except Exception as e:
            print("[ERROR] An error occurred!" + str(e))
            stopThread = True

def kickUser(userName):
    if userName in usernames:
        # calculates the index of the user to kick, then pulls user index from clientList to kick user. and removes user from clientList.

        userIndex = usernames.index(userName)
        userToKick = clientList[userIndex]
        clientList.remove(userToKick)
        userToKick.send("[!] You were kicked by admin.".encode('ascii'))
        userToKick.close()
        usernames.remove(userName)
        broadcastHandler(f"[!] {userName} was kicked by admin.").encode('ascii')
        print(f"[!] [KICK USER PARSED] \n {userName} was kicked by admin.".encode('ascii'))

if __name__ == '__main__':
    while True:

        client, address = S.accept()

        # TO START RSA ENCRYPTION (LISTEN FOR PUBLIC KEY)
        client.send(PUBLIC_KEY.save_pkcs1("PEM"))
        PUBLIC_PARTNER = rsa.PublicKey.load_pkcs1(client.recv(1024)) #, 'PEM')

        client.send("USER".encode('ascii'))
        username = client.recv(1024)
        #encryptedUsr = rsa.decrypt(client.recv(1024), PRIVATE_KEY).decode()

       # usernames.append(encryptedUsr)
        clientList.append(client)

        print(f"[!] {username} has joined the chat!")
        print(f"[!] {str(address)} has connected.")
        print(f"[!] [SECURITY KEY] \n {PUBLIC_PARTNER}!")

        msg = f"[!] {username}"
        # encryptedMsg = rsa.encrypt(msg.encode(), PUBLIC_PARTNER)
        # broadcastHandler(msg)

        #roadcastHandler(encryptedMsg)
        #broadcastHandler(msg)
       # broadcastHandler(f"[!] {username} has joined the chat!").encode('ascii')
        #client.send("Connected to server!".encode('ascii'))
        thread = threading.Thread(target=receiveHandler, args=(client,))
        thread.start()