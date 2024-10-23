#ifndef CKSUM_NEW_HPP
#define CKSUM_NEW_HPP

#include <string>
#include <filesystem>


// Declaration of memcrc
unsigned long memcrc(char* b, size_t n);

// Declaration of readfile
std::string readfile(std::string fname);

#endif // CKSUM_NEW_HPP
