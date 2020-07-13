#include "socketUtils.h"

size_t recvAll(int sock, unsigned char* buf){
    unsigned char buffer[2048];  //temporary buffer
    unsigned char* temp_buf = buf;
    unsigned char* end_buf = buf + sizeof(buf);
    size_t iByteCount;
    do {
        iByteCount = recv(sock, buffer,2048,0);
        if ( iByteCount > 0 ) {
            //make sure we're not about to go over the end of the buffer
            if (!((temp_buf + iByteCount) <= end_buf))
                break;
            //fprintf(stderr, "Bytes received: %d\n",iByteCount);
            memcpy(temp_buf, buffer, iByteCount);
            temp_buf += iByteCount;
        }
        else if ( iByteCount == 0 ) {
            if(temp_buf != buf) {
                //do process with received data
            }
            else {
                fprintf(stderr, "receive failed");
                break;
            }
        }
        else {
            fprintf(stderr, "recv failed: ");
            break;
        }
    } while(iByteCount > 0 && temp_buf < end_buf);
    return iByteCount;
}