#include <iostream>
#include <string>
#include <cstddef>
#include "hash_functions.h"

size_t hash_function(const std::string& IPv4Address){
	std::hash<std::string> hasher;

	return hasher(IPv4Address);
}

size_t hash_function(const uint16_t& port){
	std::hash<uint16_t> hasher;

	return hasher(port);
}

size_t hash_function(const uint8_t& protocol){
	std::hash<uint8_t> hasher;

	return hasher(protocol);
}
