#include <assert.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mutex>
#include <unordered_map>

namespace {

void *(*sys_malloc)(size_t);
void *(*sys_calloc)(size_t, size_t);
void *(*sys_realloc)(void *, size_t);
void *(*sys_mmap)(void *, size_t, int, int, int, off_t);
int (*sys_munmap)(void *, size_t);
void (*sys_free)(void *);

void backup() {
  if (sys_malloc)
    return;
#define BACKUP(name)                                                           \
  do {                                                                         \
    sys_##name = (decltype(sys_##name))(dlsym(RTLD_NEXT, #name));              \
    assert(sys_##name);                                                        \
  } while (0)
  BACKUP(malloc);
  BACKUP(calloc);
  BACKUP(realloc);
  BACKUP(free);
  BACKUP(mmap);
  BACKUP(munmap);
#undef BACKUP
}

constexpr size_t MAX_DEPTH = 64;

struct AllocationInfo {
  size_t size_;
  void *addr_;
  size_t depth_;
  void *backtrace_[MAX_DEPTH];
  AllocationInfo(size_t size, void *addr, size_t depth, void **backtrace)
      : size_(size), addr_(addr), depth_(depth) {
    memcpy(backtrace_, backtrace, sizeof(void *) * depth);
  }
  void dump(FILE *fout) {
    uint64_t buf[MAX_DEPTH + 3];
    buf[0] = size_;
    buf[1] = (uint64_t)addr_;
    buf[2] = depth_;
    for (size_t i = 0; i < depth_; ++i)
      buf[3 + i] = (uint64_t)backtrace_[i];
    fwrite(buf, sizeof(buf[0]), 3 + depth_, fout);
  }
};

bool on = false;
std::mutex info_mtx;
std::unordered_map<void *, AllocationInfo> addr2info;
thread_local bool recur = false;

void on_malloc(size_t size, void *addr) {
  if (!on || !addr || recur)
    return;
  recur = true;

  void *bt[MAX_DEPTH];
  size_t depth = backtrace(bt, MAX_DEPTH);

  std::lock_guard<std::mutex> lk(info_mtx);
  if (addr2info.bucket_count()) {
    addr2info.emplace(addr, AllocationInfo(size, addr, depth, bt));
  }

  recur = false;
}

void on_free(void *addr) {
  if (!on || recur)
    return;
  recur = true;

  std::lock_guard<std::mutex> lk(info_mtx);
  if (addr2info.bucket_count()) {
    auto iter = addr2info.find(addr);
    if (iter != addr2info.end())
      addr2info.erase(iter);
  }

  recur = false;
}

void dump() {
  FILE *fout = fopen("/tmp/leak_dump", "wb");
  assert(fout);

  if (FILE *fin = fopen("/proc/self/maps", "r")) {
    char buf[1024];
    int sz = 0;
    while ((sz = fread(buf, 1, sizeof(buf), fin)))
      fwrite(buf, 1, sz, fout);
    fclose(fin);
  }
  fprintf(fout, "MAP_END\n");

  for (auto &p : addr2info)
    p.second.dump(fout);
  fclose(fout);
}

__attribute__((constructor)) void init() {
  backup();
  on = true;
}

__attribute__((destructor)) void fini() {
  on = false;
  dump();
}

} // namespace

////////////////////////////////////////////////////////////////////////////////

extern "C" {

void *malloc(size_t size) {
  backup();
  void *ptr = sys_malloc(size);
  on_malloc(size, ptr);
  return ptr;
}

__attribute__((noinline)) void *calloc(size_t nmemb, size_t size) {
  if (!sys_calloc)
    return nullptr; // https://stackoverflow.com/a/42900632/2785942
  void *ptr = sys_calloc(nmemb, size);
  on_malloc(nmemb * size, ptr);
  return ptr;
}

__attribute__((noinline)) void *realloc(void *ptr, size_t size) {
  backup();
  on_free(ptr);
  ptr = sys_realloc(ptr, size);
  on_malloc(size, ptr);
  return ptr;
}

void free(void *ptr) {
  backup();
  on_free(ptr);
  return sys_free(ptr);
}

__attribute__((noinline)) void *mmap(void *addr, size_t length, int prot,
                                     int flags, int fd, off_t offset) {
  backup();
  void *ptr = sys_mmap(addr, length, prot, flags, fd, offset);
  on_malloc(length, ptr);
  return ptr;
}

__attribute__((noinline)) int munmap(void *addr, size_t length) {
  backup();
  on_free(addr);
  return sys_munmap(addr, length);
}

} // extern "C"

void *operator new(size_t size) { return malloc(size); }

void operator delete(void *ptr) noexcept { free(ptr); }

void operator delete(void *ptr, size_t) noexcept { free(ptr); }
