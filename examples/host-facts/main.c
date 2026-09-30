#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <unistd.h>

int main(void) {
    char request[65536];
    if (!fgets(request, sizeof request, stdin)) return 2;
    const char *key = "\"command_id\":\"";
    char *start = strstr(request, key);
    if (!start) return 2;
    start += strlen(key);
    char id[129]; size_t n = 0;
    while (start[n] && start[n] != '"' && n < sizeof id - 1) {
        if (!((start[n] >= '0' && start[n] <= '9') || (start[n] >= 'a' && start[n] <= 'f'))) return 2;
        id[n] = start[n]; n++;
    }
    if (!n || start[n] != '"') return 2;
    id[n] = 0;
    if (!strstr(request, "\"api_version\":1") || !strstr(request, "\"action\":\"host-facts.snapshot\"")) return 2;
    struct utsname info;
    if (uname(&info) != 0) return 3;
    struct sysinfo system_info;
    if (sysinfo(&system_info) != 0) return 3;
    char hostname[256];
    if (gethostname(hostname, sizeof hostname) != 0) return 3;
    hostname[sizeof hostname-1] = 0;
    /* uname and hostname are kernel-provided strings. Escape the only JSON-sensitive bytes. */
    for (char *p=hostname; *p; ++p) if (*p=='"' || *p=='\\' || (unsigned char)*p<32) *p='_';
    printf("{\"command_id\":\"%s\",\"output\":{\"os\":\"linux\",\"arch\":\"%s\",\"hostname\":\"%s\",\"uptime_seconds\":%ld}}\n", id, info.machine, hostname, system_info.uptime);
    return 0;
}
