// helpers/utils.h
// This header file contains utility functions and structures for the server.
#ifndef UTILS_H
#define UTILS_H

// Libraries
#include <winsock2.h>

// Structure to hold client information
struct ClientInformation {
    SOCKET clientSocket;
    int port;
};

/*
* Function to receive all data from a socket.
* This function ensures that the entire specified length of data is received.
* Parameters:
* - sock: The socket to read from.
* - buffer: Pointer to the buffer where data will be stored.
* - length: The total number of bytes to read.
* Returns: The total number of bytes received, or -1 on error.
*/
int recv_all(SOCKET sock, char* buffer, int length) {
    int total_received = 0;
    while (total_received < length) {
        int n = recv(sock, buffer + total_received, length - total_received, 0);
        if (n <= 0) {
            return n; // error or connection closed
        }
        total_received += n;
    }
    return total_received;
};

#endif