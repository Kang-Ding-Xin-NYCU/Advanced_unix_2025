#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libgotoku.h"
#include "got_offsets.h"

gotoku_t *board = NULL;
int table[9][9];
int move[1200] = {0};
int step = 0;

void gop_random() {

}

int is_valid(int x, int y, int val) {
  for (int i = 0; i < 9; ++i) {
    if (table[y][i] == val || table[i][x] == val) return 0;
  }
  int sx = x / 3 * 3, sy = y / 3 * 3;
  for (int i = 0; i < 3; ++i)
    for (int j = 0; j < 3; ++j)
      if (table[sy + i][sx + j] == val) return 0;
  return 1;
}

int dfs(int px, int py) {
  for (int y = 0; y < 9; y++) {
    for (int x = 0; x < 9; x++) {
      if (table[y][x] == 0) {
        for (int v = 1; v <= 9; v++) {
          if (is_valid(x, y, v)) {
            table[y][x] = v;
            if (dfs(px, py)) return 1;
            table[y][x] = 0;
          }
        }
        return 0;
      }
    }
  }
  return 1;
}

void solver(gotoku_t *board) {
  int fixed[9][9] = {0};

  for (int y = 0; y < 9; y++) {
    for (int x = 0; x < 9; x++) {
      table[y][x] = board->board[y][x];
      if (table[y][x] != 0) fixed[y][x] = 1;
    }
  }

  step = 0;
  int x = board->x;
  int y = board->y;

  if (!dfs(x, y)) {
    return;
  }
  while (x > 0) move[step++] = 12, x--;
  while (y > 0) move[step++] = 14, y--;

  for (int y0 = 0; y0 < 9; y0++) {
    for (int x0 = 0; x0 < 9; x0++) {
      if (!fixed[y0][x0]) {
        while (x < x0) move[step++] = 13, x++;
        while (x > x0) move[step++] = 12, x--;
        while (y < y0) move[step++] = 15, y++;
        while (y > y0) move[step++] = 14, y--;
        move[step++] = table[y0][x0];
      }
    }
  }

  for (int i = step; i < MAX_GOP; i++) {
    move[i] = 0;
  }
}

const char* gop_func_name(int code) {
  switch (code) {
    case 1: return "gop_fill_1";
    case 2: return "gop_fill_2";
    case 3: return "gop_fill_3";
    case 4: return "gop_fill_4";
    case 5: return "gop_fill_5";
    case 6: return "gop_fill_6";
    case 7: return "gop_fill_7";
    case 8: return "gop_fill_8";
    case 9: return "gop_fill_9";
    case 12: return "gop_left";
    case 13: return "gop_right";
    case 14: return "gop_up";
    case 15: return "gop_down";
    default: return "NOP or Unknown";
  }
}

void got_modify(void *main_addr) {
  uintptr_t base_addr = (uintptr_t) main_addr - MAIN_OFFSET;

  for (int i = 0; i < MAX_GOP; i++) {
    uintptr_t got_entry = base_addr + got_offset_list[i];
    uintptr_t page_start = got_entry & ~0xfff;
    mprotect((void *)page_start, 0x1000, PROT_READ | PROT_WRITE);

    switch (move[i]) {
      case 1:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_1");
        break;
      case 2:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_2");
        break;
      case 3:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_3");
        break;
      case 4:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_4");
        break;
      case 5:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_5");
        break;
      case 6:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_6");
        break;
      case 7:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_7");
        break;
      case 8:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_8");
        break;
      case 9:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_fill_9");
        break;

      case 12:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_left");
        break;
      case 13:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_right");
        break;
      case 14:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_up");
        break;
      case 15:
        *(void **)got_entry = dlsym(RTLD_NEXT, "gop_down");
        break;
    }
  }
}

gotoku_t *game_load(const char *path) {
    gotoku_t* (*ori_game_load)(const char*) = dlsym(RTLD_NEXT, "game_load");
    board = ori_game_load(path);
    void *(*game_get_ptr)() = dlsym(RTLD_NEXT, "game_get_ptr");
    
    if (!board) {
      return NULL;
    }
    solver(board);
    got_modify(game_get_ptr());
    return board;
}

int game_init() {
    void (*ori_game_init)() = dlsym(RTLD_NEXT, "game_init");
    ori_game_init();
    void *(*game_get_ptr)() = dlsym(RTLD_NEXT, "game_get_ptr");
    fprintf(stderr, "UP113_GOT_PUZZLE_CHALLENGE\n");
    fprintf(stderr, "SOLVER: _main =  %p\n", game_get_ptr());
    return 0;
}