// helpers/helper.h
// This header file contains helper structures for the server.
#ifndef HELPER_H
#define HELPER_H

// Libraries
#include <winsock2.h>
#include <cstdint>

// Structure to hold capture context
struct CaptureCtx {
    int linktype;
    size_t l2len;
};

#endif