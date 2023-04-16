from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
from socket import gethostbyaddr

#8 is the value of the ICMP echo message request used in ping
ICMP_ECHO_REQUEST = 8

#calculate checksum of input string which is used to ensure
#the integrity of the ICMP message
#
def checksum(string):
    csum = 0
    # initialize to the largest even number less than or equal to the string
    countTo = (len(string) // 2) * 2
    count = 0
    #loop through the string, take in 2 bytes at a time
    #combine them into a 16 bit value
    #and add it to the current csum
    #and ensure csum stayes within 32 bits
    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2
    # if the string length is odd, add the last byte to csum and ensure it stays within 32 bits
    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff
    # fold csum into 16 bits by adding the upper 16 bits to the lower 16 bits
    # take the one's compliment of the 16 bit csum and swap its bytes to get the final checksum value
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



#we keep waiting till we get a message or run out of time after pinging the server first
#recieve ICMP response from the server
def receiveOnePing(mySocket, ID, timeout, destAddr):
    #set time left to the input timeout
    timeLeft = timeout

    #enter a loop until there's a response or the timeout is reached
    while 1:
        #record the starttime of the select function
        startedSelect = time.time()
        #use select to wait for a response from the socket or a timeout
        whatReady = select.select([mySocket], [], [], timeLeft)
        #calculate the time spent in the select function
        howLongInSelect = (time.time() - startedSelect)
        #check if the socket is empty which means a timeout occurred
        #and return timeout
        if whatReady[0] == []:  # Timeout
            return "Request timed out."
        #record the time the response was recieved
        timeReceived = time.time()
        #recieve the ICMP packet and source address
        recPacket, addr = mySocket.recvfrom(1024)

        #extract the ICMP header from the IP packet
        # Fill in start##################################################################

        # Fetch the ICMP header from the IP packet

        #here we extract the ICMP header from the recieved IP packet('recPacket')
        #the ip header is 20 bytes,
        #then comes the ICMP header is 8 bytes
        # ICMp header includes  tpe, code, checksum, id and sequence (160 - 191 bits)
        icmpHeader = recPacket[20:28] #extract the ICMP header from 20 to 28




        #struct.uppack function unpacks the ICMP header's binary data
        #the data string bbHHh describes the data structure:
        # b:signed char 1byte
        #H: unsigned short(2 bytes)
        #h: short (2bytes)
        #so....
        #b = type
        #b = code
        #B = checksum
        #B = ID
        #h = sequence
        type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."
        if type == 0 and packetID==ID:
            byteSize = len(recPacket)
            timeSent = struct.unpack("d", recPacket[28:28 + struct.calcsize("d")])[0]
            delay = timeReceived - timeSent
            ttl = struct.unpack("c", recPacket[8:9])[0]
            return delay, (byteSize, delay, ttl)
        else:
            return("Request timed out.",['0', '0.0','0','0.0'])


        # Fill in end####################################################################

        #update timeleft and check if it's less than or equal to 0, indicating timeout
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."




#function to send an ICMP request to the destination server
#need it to send a ping to the server
# we send to the server a header with some data
def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data

    #initialize the ICMP header with type code checksum id and sequence, all initially set to 0 except sequence is 1 and type
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) # these are bbHHh arguments
    #pack the current time as binary data, this will be sent in the ICMP packet
    #this will be used to calc rrt when pong is recieved
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    #checksum is for checking the integrity of the ICMP packet
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff #mac od
    else:
        myChecksum = htons(myChecksum) #other platforms

    # repack the header with the correct checsum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    #combine it with data for final packet
    packet = header + data

    #send the packet to the destination server using the socket
    #sendto function send packets to addreess as a tuple containg IP and port
    #in this case, ip= destAddr and port is 1
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


#this function combines the sending and recieving parts
#and creates a socket to connect to the server and then send the ping + wait for pong
def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")

    # SOCK_RAW is a powerful socket type. For more details:   https://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay




#this function does the whole process several times ping pong ping pong etc
#here we find the server's address
#we create an empty dataframe to store info about every pin pong round
#we do four rounds with the server , waiting 1 second btw each round
#we save infor of each round bytes rtt ttl  in the table
#we count how many times the server respnded and how many times it didn't (packet_loss and packet_recv)
#we calculate the shortest, average, longest and how spread out the responses were
def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,   
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("\nPinging " + dest + " using Python:")
    print("")
    
    response = pd.DataFrame(columns=['bytes','rtt','ttl']) #This creates an empty dataframe with 3 headers with the column specific names declared

    #Send ping requests to a server separated by approximately one second
    #Add something here to collect the delays of each ping in a list so you can calculate vars after your ping
    delays = []
    for i in range(0,4): #Four pings will be sent (loop runs for i=0, 1, 2, 3)

        delay, statistics = doOnePing(dest, timeout) #what is stored into delay and statistics?
        # recBytes, rtt, ttl = statistics
        # delays.append(delay)
        # response = response.append({'bytes': recBytes, 'rtt': delay, 'ttl': ttl}, ignore_index=True)
        # print("Reply from {}: bytes={} time={:.2f}ms TTL={}".format(dest, recBytes, delay * 1000, ord(ttl)))

        # if statistics:
        recBytes, rtt, ttl = statistics
        delays.append(delay)
        response = response.append({'bytes': recBytes, 'rtt': delay, 'ttl': ttl}, ignore_index=True)
        print("Reply from {}: bytes={} time={:.2f}ms TTL={}".format(dest, recBytes, delay * 1000, ord(ttl)))
        # elif isinstance(delay, str):
        #     response = response.append({'bytes': 0, 'rtt': 0, 'ttl': 0}, ignore_index=True)
        #     print("Request timed out.")

        #response = #store your bytes, rtt, and ttle here in your response pandas dataframe. An example is commented out below for vars

        #print(delay)
        time.sleep(1)  # wait one second
    
    packet_lost = 0
    packet_recv = 0
    #fill in start. UPDATE THE QUESTION MARKS
    for index, row in response.iterrows():
        if row['rtt'] == 0: #access your response df to determine if you received a packet or not
            packet_lost = packet_lost + 1
        else:
            packet_recv = packet_recv + 1

    print("\n--- {} ping statistics ---".format(host, dest))
    print("4 packet transmitted, {} packets recieved, {:.1f}% packet loss".format(packet_recv, packet_lost,
                                                                              (packet_lost / 4) * 100))
    #fill in end

    #You should have the values of delay for each ping here structured in a pandas dataframe; 
    #fill in calculation for packet_min, packet_avg, packet_max, and stdev
    vars = pd.DataFrame(columns=['min', 'avg', 'max', 'stddev'])
    vars = vars.append({'min':str(round(response['rtt'].min() * 1000, 2)), 'avg':str(round(response['rtt'].mean() * 1000, 2)),'max':str(round(response['rtt'].max() * 1000, 2)), 'stddev':str(round(response['rtt'].std() * 1000,2))}, ignore_index=True)
    print (vars) #make sure your vars data you are returning resembles acceptance criteria
    return vars

#this part of the code checks if we are running this file directly and starts the process is we are
if __name__ == '__main__':
    #ping("127.0.0.1")
    ping("google.com")
    ping("nyu.edu")

