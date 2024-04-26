import socket, sys, threading, rsa, traceback
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

stopThread  = False
PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(1024)
PUBLIC_PARTNER = None

global userName, password, client
userName = input ("[!] Enter your username: ")
if userName == "":
    print("[ERROR] Please enter a valid username")
if userName == "admin":
    password = input("[!] Enter your password: ")
    if password == "":
        print("[ERROR] Please enter a valid password")

hostname = socket.gethostname()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((hostname, 8000))

PUBLIC_PARTNER = rsa.PublicKey.load_pkcs1(client.recv(1024))
client.send(PUBLIC_KEY.save_pkcs1("PEM"))
print("[!] PUBLIC KEY: \n" + str(PUBLIC_KEY))
print("[!] PRIVATE KEY: \n" + str(PRIVATE_KEY))

def receiveHandler():
    while True:
        global stopThread
        if stopThread:
            break
        try:
            message = client.recv(1024).decode('ascii')
#            encryptedMsg = rsa.decrypt(client.recv(1024), PRIVATE_KEY).decode()

            print("[RECEIVE HANDLER ")
            print("[MESSAGE] -- CLIENT " + message)
           # print("[DECRYPTED MESSAGE] -- CLIENT " + encryptedMsg)

            if message == "USER": #or encryptedMsg == "USER":

                client.send(userName.encode('ascii'))
                nextMessage = client.recv(1024).decode('ascii')
              #  nextMessageEncrypted = rsa.decrypt(client.recv(1024), PRIVATE_KEY).decode()
                print("[NEXT - MESSAGE] -- CLIENT " + nextMessage)
              #  print("[NEXT - MESSAGE] -- DECRYPTED " + nextMessageEncrypted)

                if nextMessage == "PASS": # or encryptedMsg == "PASS":

                    client.send(password.encode('ascii'))
                    if client.recv(1024).decode('ascii') == "REFUSE":
                        print("[ERROR] Connection was refused! Please enter a valid password.")
                        stopThread = True

                # CHECKS IF ADMIN SETS KICK OR BAN SIGNAL
                elif nextMessage == "BAN":
                    print("[ERROR] Connection refused because of ban.")
                    client.close()
                    stopThread = True

                elif nextMessage == "KICK":
                    print("[ERROR] Connection was kicked by admin.")
                    client.close()
                    stopThread = True

            else:
                print("[!] CLIENT MESSAGE " + message)

        except Exception as e:
            print("[ERROR] An error occurred!" + str(e))
            print(traceback.print_exc())

            client.close()
            break


def writeHandler():
    while True:
        if stopThread:
            client.close()
            break


        ''' CODE TO CHECK IF USER NAME == ADMIN, WHICH GRANTS KICK AND BAN PRIVILEGES.'''
        message = f"{userName}: {input('')}"
        if message[len(userName)+2:].startswith('/'):
            if userName == "admin":
                if message[len(userName)+2:].startswith('/kick'):
                    client.send(f"KICK {message[len(userName)+2+6:]}".encode('ascii'))
                elif message[len(userName)+2:].startswith('/ban'):
                    client.send(f"BAN {message[len(userName)+2+5:]}".encode('ascii'))

            else:
                print("[ERROR] You do not have permission to use this command.")
        else:
          #  encryptedMsg = rsa.encrypt(message.encode('ascii'), PUBLIC_PARTNER)
            print("[MESSAGE] -- CLIENT " + message)
            client.send(message.encode('ascii'))
            #stopThread = True

        client.send(message.encode('ascii'))
        #stopThread = True

        #  print("[ENCRYPTED MESSAGE] -- CLIENT " + str(encryptedMsg))
            #client.send(encryptedMsg)


     #   encryptedMsg = rsa.encrypt(message.encode('ascii'), PUBLIC_PARTNER)
       # client.send(encryptedMsg)
        #client.send(message.encode('ascii'))




if __name__ == '__main__':
   # main()

    try:
        receivingThread = threading.Thread(target=receiveHandler)
        receivingThread.start()
        writingThread = threading.Thread(target=writeHandler)
        writingThread.start()


    except Exception as e:
        print("[ERROR] An error occurred! IN MAIN " + str(e))


