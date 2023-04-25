# Import necessary libraries
from socket import *  # Import socket library for networking
import os  # Import operating system library for process management
import sys  # Import system library for system-specific parameters and functions
import struct  # Import struct library for working with C-style data structures
import time  # Import time library for working with time
import select  # Import select library for I/O multiplexing
import binascii  # Import binascii library for working with binary data
import pandas as pd  # Import pandas library for data manipulation
import warnings  # Import warnings library for handling warnings
warnings.simplefilter(action='ignore', category=FutureWarning)  # Suppress FutureWarning
from socket import gethostbyaddr  # Import gethostbyaddr function for reverse DNS lookup

# Define constant for ICMP echo request used in ping
ICMP_ECHO_REQUEST = 8

#calculate checksum of input string which is used to ensure
#the integrity of the ICMP message
# Function to calculate the checksum of a given string
def checksum(string):
    """
        Calculate the checksum of a given string.

        Args:
        string (bytes): The string for which the checksum is to be calculated.

        Returns:
        int: The final checksum value.
        """
    csum = 0  # Initialize checksum
    countTo = (len(string) // 2) * 2  # Calculate largest even number less than or equal to the string length
    count = 0  # Initialize count variable for the loop

    # Loop through the string, process two bytes at a time, and update the checksum
    # combine them into a 16 bit value
    # and add it to the current csum
    # and ensure csum stayes within 32 bits
    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])  # Combine two bytes into a 16-bit value
        csum += thisVal  # Add the 16-bit value to the current checksum
        csum &= 0xffffffff  # Ensure the checksum stays within 32 bits
        count += 2  # Increment count by 2 for the next two bytes

    # If the string length is odd, process the last byte and update the checksum
    # add the last byte to csum and ensure it stays within 32 bits
    if countTo < len(string):
        csum += (string[len(string) - 1])  # Add the last byte to the checksum
        csum &= 0xffffffff  # Ensure the checksum stays within 32 bits

    # Fold the checksum into 16 bits and compute the final checksum value
    csum = (csum >> 16) + (csum & 0xffff)  # Add upper 16 bits to lower 16 bits
    csum = csum + (csum >> 16)  # Add any carry to the result
    answer = ~csum  # Take the one's complement of the 16-bit checksum
    answer = answer & 0xffff  # Keep only the lower 16 bits
    answer = answer >> 8 | (answer << 8 & 0xff00)  # Swap bytes and return the final checksum value
    return answer

# Function to receive one ping response
#we keep waiting till we get a message or run out of time after pinging the server first
#recieve ICMP response from the server
def receiveOnePing(mySocket, ID, timeout, destAddr):
    """
        Receive one ping response.

        Args:
        mySocket (socket): The socket used for communication.
        ID (int): The process ID.
        timeout (float): Time to wait for a response in seconds.
        destAddr (str): The destination IP address.

        Returns:
        str: A message indicating success or timeout.
        dict: A dictionary containing the packet statistics.
        """
    timeLeft = timeout  # Set time left to the input timeout value

    # Loop until there's a response or the timeout is reached
    while 1:
        startedSelect = time.time()  # Record the start time of the select function
        whatReady = select.select([mySocket], [], [], timeLeft)  # Wait for a response from the socket or a timeout
        howLongInSelect = (time.time() - startedSelect)  # Calculate the time spent in the select function

        # Check if the socket is empty, which means a timeout occurred, and return "Request timed out."
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()  # Record the time the response was received
        recPacket, addr = mySocket.recvfrom(1024)  # Receive the ICMP packet and source address

        # Extract the ICMP header from the IP packet
        icmp_header = recPacket[20:28]  # Extract the ICMP header from the received packet
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh",
                                                                               icmp_header)  # Unpack the ICMP header into its components

        # Check if the ICMP type and ID match the expected values
        if icmp_type != 0 or icmp_id != ID:
            continue  # If the ICMP type or ID doesn't match, continue with the next iteration of the loop

        #extract the ICMP header from the IP packet
        # Fill in start##################################################################
        # Fill in start
        # Extract payload and calculate RTT and TTL
        payload = struct.unpack("d", recPacket[28:])[0]  # Extract the payload (timestamp) from the packet
        rtt = (timeReceived - payload) * 1000  # Calculate Round Trip Time (RTT) in milliseconds
        ttl = struct.unpack("B", recPacket[8:9])[0]  # Extract Time To Live (TTL) value from the packet

        # Return the ping result and a dictionary containing the packet statistics
        return f"Reply from {destAddr}: bytes={len(recPacket)} time={rtt:.2f}ms TTL={ttl}", {
            "bytes": len(recPacket), "rtt": rtt, "ttl": ttl}

        # Update time left and check if it's less than or equal to 0, indicating a timeout
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


#function to send an ICMP request to the destination server
#need it to send a ping to the server
# we send to the server a header with some data
def sendOnePing(mySocket, destAddr, ID):
    """
       Send one ICMP request to the destination server.

       Args:
       mySocket (socket): The socket used for communication.
       destAddr (str): The destination IP address.
       ID (int): The process ID.
       """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)


#   header =  This line of code is packing values into a binary string using the struct.pack function. The struct.pack function takes a format specifier and a sequence of values as arguments, and it returns a packed binary string.
#
# Here's a breakdown of the format specifier and values being passed to struct.pack:
#
# "bbHHh": This is the format specifier. Each character represents the data type and size of the values being packed. In this case, there are five values to pack:
#
# b: signed char (1 byte)
# b: signed char (1 byte)
# H: unsigned short (2 bytes)
# H: unsigned short (2 bytes)
# h: signed short (2 bytes)
# ICMP_ECHO_REQUEST: The value of the ICMP Echo Request type (8), which is the first value in the packed binary string.
#
# 0: The code, which is set to 0 for ICMP Echo Request messages. This is the second value in the packed binary string.
#
# myChecksum: The calculated checksum for the ICMP packet. This is the third value in the packed binary string.
#
# ID: The process ID of the current process, used to uniquely identify the ICMP packet. This is the fourth value in the packed binary string.
#
# 1: The ICMP sequence number, set to 1 for this implementation. This is the fifth value in the packed binary string.
#
# The result is a packed binary string that represents the ICMP header, which is later combined with the data to create the complete ICMP packet.

    myChecksum = 0  # Initialize checksum
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    # initialize the ICMP header with type code checksum id and sequence, all initially set to 0 except sequence is 1 and type
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID,
                         1)  # Create a dummy header with a 0 checksum
    # pack the current time as binary data, this will be sent in the ICMP packet
    # this will be used to calc rrt when pong is recieved


# This line of code is packing the current timestamp into a binary string using the `struct.pack` function. Here's a breakdown of the format specifier and values being passed to `struct.pack`:
#
# - `"d"`: This is the format specifier. It represents a double-precision floating-point number (8 bytes) in the packed binary string.
#
# - `time.time()`: This function call returns the current time in seconds since the epoch (January 1, 1970) as a floating-point number.
# 
# The result is a packed binary string that represents the current timestamp. This timestamp is used as the payload in the ICMP packet, which is later used to calculate the Round-Trip Time (RTT) when the corresponding ICMP response is received.

    data = struct.pack("d", time.time())  # Pack the current time as binary data for the ICMP packet
    # Calculate the checksum on the data and the dummy header.
    # checksum is for checking the integrity of the ICMP packet
    # Calculate the checksum on the data and the dummy header
    myChecksum = checksum(header + data)  # Calculate the checksum for the header and data sent as one argument

    # Get the right checksum, and put it in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff  # Convert 16-bit integers to network byte order on macOS
    else:
        myChecksum = htons(myChecksum) # Convert 16-bit integers from host to network  byte order
        # Convert 16-bit integers to network byte order on other platforms

    # Repack the header with the correct checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data  # Combine the header and data to create the final packet

    # send the packet to the destination server using the socket
    # sendto function send packets to addreess as a tuple containg IP and port
    # in this case, ip= destAddr and port is 1
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

# Function that combines the sending and receiving parts
#and creates a socket to connect to the server and then send the ping + wait for pong
def doOnePing(destAddr, timeout):
    """
        Perform one ping-pong iteration with the server.

        Args:
        destAddr (str): The destination IP address.
        timeout (float): Time to wait for a response in seconds.

        Returns:
        tuple: Contains the delay and a dictionary with packet statistics.
        """
    icmp = getprotobyname("icmp")  # Get the protocol number for ICMP
    mySocket = socket(AF_INET, SOCK_RAW, icmp)  # Create a raw socket for ICMP
    myID = os.getpid() & 0xFFFF

    # Get the current process ID and bitwise AND with 0xFFFF to obtain a 16-bit number. This is to ensure that the process ID fits within the 16-bit range used in ICMP packets.

    sendOnePing(mySocket, destAddr,myID)  # Send a single ICMP request to the destination server. mySocket is the socket object, destAddr is the destination IP address, and myID is the process ID.

    delay = receiveOnePing(mySocket, myID, timeout,destAddr)  # Receive a single ICMP response from the server. The parameters are the same as in sendOnePing, with the addition of the timeout.

    mySocket.close()  # Close the socket once the response has been received. This is important to release resources and prevent potential memory leaks.

    return delay  # Return the delay between sending and receiving the ICMP packets. This will be used to calculate statistics later on.


# Function that runs the ping process several times and collects statistics
#this function does the whole process several times ping pong ping pong etc
#here we find the server's address
#we create an empty dataframe to store info about every pin pong round
#we do four rounds with the server , waiting 1 second btw each round
#we save infor of each round bytes rtt ttl  in the table
#we count how many times the server respnded and how many times it didn't (packet_loss and packet_recv)
#we calculate the shortest, average, longest and how spread out the responses were


def ping(host, timeout=1):
    """
        Perform several ping-pong iterations with the server and collect statistics.

        Args:
        host (str): The hostname or IP address of the target server.
        timeout (float, optional): Time to wait for a response in seconds. Defaults to 1.
        """
    dest = gethostbyname(
        host)  # Resolve the host to its IP address. This allows us to ping servers by hostname or IP address.

    print("\nPinging " + dest + " using Python:")
    print("")

    response = pd.DataFrame(columns=['bytes', 'rtt','ttl'])  # Create an empty DataFrame to store packet statistics. This will be used to compute statistics at the end of the process.

    packet_lost = 0  # Initialize the packet_lost counter. This will be used to calculate the packet loss percentage.
    packet_recv = 0  # Initialize the packet_recv counter. This will be used to track the number of received packets.

    # Perform four ping-pong iterations with the server
    for i in range(0, 4):
        result = doOnePing(dest,timeout)  # Perform a single ping-pong iteration with the server. dest is the destination IP address and timeout is the time to wait for a response.


        if len(result) == 2:
            # Check if the result contains both delay and statistics. This is to ensure that the result is in the expected format.
            delay, statistics = result
            # Unpack the result into delay and statistics variables. We will use these values to update the response DataFrame.
        else:
            print(result)
            continue
            # If the result is unexpected, continue with the next iteration.

        # Append the statistics to the response DataFrame
        if statistics:
            response = response.append(statistics,ignore_index=True)
            # Add the statistics to the DataFrame. This will update the DataFrame with the new values.
        else:
            response = response.append({'bytes': 0, 'rtt': 0, 'ttl': 0},ignore_index=True)
            # If no statistics are provided, add zeros to the DataFrame.

        print(delay)  # Print the delay for the current iteration.
        time.sleep(1)  # Wait for one second before the next iteration. This is to simulate the behavior of the standard ping command.

    # Calculate the number of packets lost and received
    for index, row in response.iterrows():  # Iterate through each row in the response DataFrame.
        if row['rtt'] == 0:  # If the RTT is 0, it means that the
            # packet was lost.
            packet_lost += 1  # Increment the packet_lost counter.
        else:
            packet_recv += 1  # Increment the packet_recv counter for received packets.

            # Print the ping statistics
    print(f"\n--- {host} ping statistics ---")
    if len(response) > 0:
        # Check if there are any packets in the response DataFrame.
        # This means at least one packet was transmitted during the ping process.
        print(
            f"{len(response)} packets transmitted, {packet_recv} packets received, {packet_lost / len(response) * 100.0:.1f}% packet loss")
        # Print the total number of packets transmitted (length of the response DataFrame).
        # Also, print the number of packets received (packet_recv) and calculate the packet loss percentage.
    else:
        print("4 packets transmitted, 0 packets received, 100% packet loss")
        # If there are no packets in the response DataFrame, it means all packets were lost.
        # Print the packet loss message.

        # Calculate the minimum, average, maximum, and standard deviation of the RTTs
    if packet_recv == 0:
        # Check if no packets were received (packet_recv is 0).
        vars = pd.DataFrame({"min": [0], "avg": [0.0], "max": [0], "stddev": [0.0]})
        # If no packets were received, all statistics are set to 0.
        # Create a DataFrame with zero values for minimum, average, maximum, and standard deviation of RTTs.
    else:
        # If there are received packets, calculate the statistics.
        vars = pd.DataFrame({"min": [round(response['rtt'].min(), 2)],"avg": [round(response['rtt'].mean(), 2)],
                             "max": [round(response['rtt'].max(), 2)],"stddev": [round(response['rtt'].std(), 2)]})
        # Calculate the minimum of the RTTs in the response DataFrame and round it to 2 decimal places.
        # Calculate the average (mean) of the RTTs in the response DataFrame and round it to 2 decimal places.
        # Calculate the maximum of the RTTs in the response DataFrame and round it to 2 decimal places.
        # Calculate the standard deviation of the RTTs in the response DataFrame and round it to 2 decimal places.
        # Create a DataFrame with calculated values for minimum, average, maximum, and standard deviation of RTTs.
    print(vars)
    return vars







if __name__ == '__main__':
    # ping("127.0.0.1")
    ping("google.com")
    ping("nyu.edu")
    ping("yahoo.com")
