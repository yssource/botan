/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AF_ALG_PROV_H_
#define BOTAN_AF_ALG_PROV_H_

#include <memory>
#include <string>

namespace Botan {

class BlockCipher;
class StreamCipher;
class HashFunction;
class Cipher_Mode;

std::unique_ptr<HashFunction> create_af_alg_hash(const std::string& name);

std::unique_ptr<BlockCipher> create_af_alg_block_cipher(const std::string& name);

std::unique_ptr<StreamCipher> create_af_alg_ctr_mode(const std::string& name);

std::unique_ptr<Cipher_Mode> create_af_alg_cipher(const std::string& name);

}

#endif
