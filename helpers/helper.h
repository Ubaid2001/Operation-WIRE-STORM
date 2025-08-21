#ifndef HELPER_H
#define HELPER_H

#include <winsock2.h>
#include <cstdint>

struct CaptureCtx {
    int linktype;
    size_t l2len;
};

#endif