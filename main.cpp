// main.cpp
// Operation Wire Storm Reloaded - Main Server Application

//Libraries
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <thread>
#include <vector>
#include <atomic>

// Custom includes
#include "./helpers/protocol_headers.h"
#include "./helpers/config.h"
#include "PacketOperations.h"
#include "./helpers/utils.h"


// Global variable, checks if server is running.
std::atomic<bool> server_running(true);

// Function to quit the server.
void console_listener() {
    std::string input;
    while (server_running) {
        std::getline(std::cin, input);
        if (input == "quit") {
            server_running = false;  // signal server to stop
            break;
        }
    }
}

/* Function to create a listening socket.
** Parameter: port - the port to listen on. 
** Returns: SOCKET on success, INVALID_SOCKET on failure. 
*/
SOCKET create_listen_socket(int port) {

    // Create a socket.
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        std::cerr << "socket() failed: " << WSAGetLastError() << "\n";
        return INVALID_SOCKET;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;


    // Bind socket to address and port.
    if (bind(s, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind(" << port << ") failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    // Check socket is listening on specified port.
    // If port 3333 then only 1 connection allowed.
    if (listen(s, port == 33333 ? 0 : SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen(" << port << ") failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    std::cout << "Listening on " << IP_ADDRESS << ":" << port << "\n";
    return s;
}

// Function to configure the server.
void config_server() {

    // Initialize Winsock.
    // This is required for socket operations.
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    SOCKET s1 = create_listen_socket(PORT1);
    SOCKET s2 = create_listen_socket(PORT2);
    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // Set up the master socket set.
    // This will allow us to monitor multiple sockets.
    fd_set master{};
    FD_ZERO(&master);
    FD_SET(s1, &master);
    FD_SET(s2, &master);

    // Initialize client information vector.
    std::vector<ClientInformation> clients;

    // Initialise thread to listen for console commands.
    std::thread console_thread(console_listener);

    std::cout << "Server running.\n";

    // Main server loop.
    // This will run until the server is stopped.
    while (server_running) {

        fd_set readset = master;
        timeval timeout{};
        timeout.tv_sec = 1; 
        timeout.tv_usec = 0;

        // Wait for activity on any socket.
        // This will block until a socket is ready or timeout occurs.
        int rc = select(0, &readset, nullptr, nullptr, &timeout);
        if (rc == SOCKET_ERROR) break;

        for (u_int i = 0; i < readset.fd_count; ++i) {
            SOCKET sock = readset.fd_array[i];

            // Check if socket is one of the listening sockets.
            // If so, accept new connections.
            // Otherwise, handle data from existing connections.
            if (sock == s1 || sock == s2) {
                // Accept new connection.
                SOCKET c = accept(sock, nullptr, nullptr);
                if (c != INVALID_SOCKET) {
                    FD_SET(c, &master);
                    int port = (sock == s1) ? PORT1 : PORT2;
                    clients.push_back({c, port});
                    std::cout << "New client on port " << port << "\n";
                }

            } else {
                // Handle data from existing client.
                uint8_t header[8];

                // Read header
                int n = recv_all(sock, reinterpret_cast<char*>(header), 8);
                if (n <= 0) {
                    closesocket(sock);
                    FD_CLR(sock, &master);
                    continue;
                }

                // Validate header
                if (header[0] != MAGIC_BYTE) {
                    std::cerr << "[CTMP] Invalid Magic Byte, dropping.\n";
                    continue;
                }

                uint16_t payload_length;
                memcpy(&payload_length, &header[2], sizeof(payload_length));
                payload_length = ntohs(payload_length);

                // Read payload fully
                std::vector<uint8_t> payload(payload_length);
                n = recv_all(sock, reinterpret_cast<char*>(payload.data()), payload_length);
                if (n <= 0) {
                    closesocket(sock);
                    FD_CLR(sock, &master);
                    continue;
                }

                // Broadcast full message (header + payload)
                std::vector<uint8_t> fullmsg(8 + payload_length);
                memcpy(fullmsg.data(), header, 8);
                memcpy(fullmsg.data() + 8, payload.data(), payload_length);

                for (const auto& ci : clients) {
                    if (ci.clientSocket != sock && ci.port == PORT2) {
                        
                        send(ci.clientSocket, reinterpret_cast<char*>(fullmsg.data()), fullmsg.size(), 0);
                    }
                }

            }
        }
    }

    // Waits for the console thread to finish.
    console_thread.join();

    // Clean up: close all client sockets.
    closesocket(s1);
    closesocket(s2);
    WSACleanup();
    std::cout << "Server shut down cleanly.\n";
}

// Main function to start the server and packet capture.
int main() {

    std::cout << "Operation Wire Storm Reloaded started. Enter 'quit' to exit program.\n";

    PacketOperations packetOps;

    // Start Npcap capture in background
    std::thread sniffer(&PacketOperations::start_capture, &packetOps);

    // Run server
    config_server();

    //wait for sniffer thread to finish
    sniffer.join();

    std::cout << "End of program.\n";
    return 0;
}