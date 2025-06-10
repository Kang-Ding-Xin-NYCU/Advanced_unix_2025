#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include "cryptomod.h"

int main() {
    int fd = open("/dev/cryptodev", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct CryptoSetup setup;
    memset(&setup, 0, sizeof(setup));

    strcpy(setup.key, "1234567890123456");
    setup.key_len = 16;
    setup.io_mode = BASIC;
    setup.c_mode = ENC;

    if (ioctl(fd, CM_IOC_SETUP, &setup) < 0) {
        perror("ioctl SETUP");
        close(fd);
        return -1;
    }

    printf("Setup completed!\n");

    if (ioctl(fd, CM_IOC_CLEANUP) < 0) {
        perror("ioctl CLEANUP");
    }

    close(fd);
    return 0;
}
