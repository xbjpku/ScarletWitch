// Utility: notify the supervisor to reload whitelist.conf
// Usage: ./reload
// Called by opencode when submitting a new task.

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CTRL_SOCK_PATH "/run/whitelist-supervisor.sock"

int notify_reload(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, CTRL_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    if (send(fd, "RELOAD", 6, 0) < 0) {
        perror("send");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int main(void) {
    if (notify_reload() == 0)
        printf("Whitelist reload triggered.\n");
    else
        fprintf(stderr, "Failed to trigger reload.\n");
    return 0;
}
