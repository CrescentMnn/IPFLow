#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H

#include <string>
#include <cstddef>

size_t hash_function(const std::string&);

size_t hash_function(const uint16_t&);

size_t hash_function(const uint8_t&);

#endif
