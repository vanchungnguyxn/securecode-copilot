#include <cstdio>
#include <cstdlib>
#include <string>

// demo C++ snippets for scanner
void bad(const char* user, const std::string& cmd) {
  char buf[64];
  strcpy(buf, user);
  printf(user);
  std::system(cmd.c_str());
}
