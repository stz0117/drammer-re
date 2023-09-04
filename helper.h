/*
 * Copyright 2016, Victor van der Veen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HELPER_H__
#define __HELPER_H__

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <cmath>
#include <numeric>

#define G(x) (x << 30)
#define M(x) (x << 20)
#define K(x) (x << 10)

#define  B_TO_ORDER(x) (ffs(x / 4096)-1)
#define KB_TO_ORDER(x) (ffs(x / 4)-1)
#define MB_TO_ORDER(x) (ffs(x * 256)-1)

#define ORDER_TO_B(x)  ((1 << x) * 4096)
#define ORDER_TO_KB(x) ((1 << x) * 4)
#define ORDER_TO_MB(x) ((1 << x) / 256)

#define MAX_ORDER 10

#define BILLION 1000000000L
#define MILLION 1000000L

extern FILE *global_of;

static inline uint64_t get_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return BILLION * (uint64_t) t.tv_sec + (uint64_t) t.tv_nsec;
}

static inline uint64_t get_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return MILLION * (uint64_t) tv.tv_sec + tv.tv_usec;

}

static inline int get_status_info(char find[] = NULL) {
    int status_fd = open("/proc/self/status", O_RDONLY);
    const int BUF_LEN = 256;
    char buf[BUF_LEN] = "";
    while (true) {
        int count = read(status_fd, buf, BUF_LEN-1);
        buf[count] = 0;
        if (find != NULL) {
            char *p = strstr(buf, find);
            if (p != NULL) {
                if(p + 19 <= buf + BUF_LEN) {
                    *(p + 19) = 0;
                    printf("%s", p);
                } else {
                    read(status_fd, buf, 20);
                    buf[p+19 - buf+BUF_LEN] = 0;
                    printf("%s%s", p, buf);
                }
                break;
            }
            lseek(status_fd, -strlen(find), SEEK_CUR);
        } else {
            printf("%s", buf);
        }
        if (count != BUF_LEN-1) break;
    }
    close(status_fd);
    return 0;
}

static int maps_fd = 0;

static inline int get_maps_info() {
//    if (maps_fd == 0) {
    maps_fd = open("/proc/self/maps", O_RDONLY);
//    }

    char buf[256] = "";
    while (true) {
        int count = read(maps_fd, buf, 255);
        buf[count] = 0;
        printf("%s", buf);
        if (count != 255) break;
    }
//    lseek(maps_fd, 0, SEEK_SET);
    close(maps_fd);
    return 0;
}

static int pagetype_fd = 0;

static inline int get_pagetype_info() {
//    if (pagetype_fd == 0) {
        pagetype_fd = open("/proc/pagetypeinfo", O_RDONLY);
//    }

    char buf[256] = "";
    while (true) {
        int count = read(pagetype_fd, buf, 255);
        buf[count] = 0;
        printf("%s", buf);
        if (count != 255) break;
    }
//    lseek(pagetype_fd, 0, SEEK_SET);
    close(pagetype_fd);
    return 0;
}

static int buddy_fd = 0;

static inline int get_buddy_info(char find[] = NULL, uint32_t free[] = NULL) {
    if (buddy_fd == 0) {
        buddy_fd = open("/proc/buddyinfo", O_RDONLY);
    }
    const int BUF_LEN = 256;
    char buf[BUF_LEN] = "";
    while (true) {
        int count = read(buddy_fd, buf, BUF_LEN-1);
        buf[count] = 0;

        if (find == NULL) {
            printf("%s", buf);
        } else {
            char *p = strstr(buf, find);
            if (p != NULL) {
                char *q = p;
                for(; *q != '\n'; q++);
                *q = 0;
                printf("%s\n", buf);
                if (free != NULL) {
                    for (int i = 0; i < 11; i++) {
                        for(; !(*p >= '0' && *p <= '9'); p++);
                        sscanf(p, "%d", &free[i]);
                        for(; !(*p == ' ' || *p == 0); p++);
                    }
                }
                break;
            }
        }

        if (count != BUF_LEN-1) break;
    }
    lseek(buddy_fd, 0, SEEK_SET);
//    close(buddy_fd);
    return 0;
}

static int pagemap_fd = 0;
static bool got_pagemap = true;

static inline uintptr_t get_phys_addr(uintptr_t virtual_addr) {
    if (!got_pagemap) return 0;
    if (pagemap_fd == 0) {
        pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
        if (pagemap_fd < 0) {
            got_pagemap = false;
            printf("Fail to open pagemap, pagemap_fd = %d\n", pagemap_fd);
            return 0;
        }
    }
    uint64_t value;
    off_t offset = (virtual_addr / PAGESIZE) * sizeof(value);
    int got = pread(pagemap_fd, &value, sizeof(value), offset);
    assert(got == 8);

    // Check the "page present" flag.
    if ((value & (1ULL << 63)) == 0) {
        printf("page not present? virtual address: %p | value: %p\n", (void *)virtual_addr, (void *)value);
        return 0;
    }

    uint64_t frame_num = (value & ((1ULL << 54) - 1));
    return (frame_num * PAGESIZE) | (virtual_addr & (PAGESIZE-1));
}

static inline int helper_clean(void) {
    close(pagetype_fd);
    close(buddy_fd);
    close(pagemap_fd);
    return 0;
}

static inline uint64_t compute_median(std::vector<uint64_t> &v) {
    if (v.size() == 0) return 0;
    std::vector<uint64_t> tmp = v;
    size_t n = tmp.size() / 2;
    std::nth_element(tmp.begin(), tmp.begin()+n, tmp.end());
    return tmp[n];
}

static inline void print(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    if (global_of != NULL) vfprintf(global_of, format, args);
    va_end(args);
}

#endif // __HELPER_H__
