/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/af_alg_prov.h>
#include <botan/internal/af_alg_util.h>
#include <botan/block_cipher.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

class AF_Alg_Block_Cipher final : public BlockCipher
   {
   public:
      AF_Alg_Block_Cipher(const std::string& lib_name,
                          const std::string& kernel_name,
                          size_t block_size,
                          const Key_Length_Specification& key_spec) :
         m_lib_name(lib_name),
         m_kernel_name(kernel_name),
         m_block_size(block_size),
         m_key_spec(key_spec),
         m_socket("skcipher", kernel_name),
         m_key_set(false)
         {}

      std::string name() const override { return m_lib_name; }

      std::string provider() const override { return "af_alg"; }

      size_t block_size() const override { return m_block_size; }

      // arbitrary number. encourage bulk operations
      size_t parallelism() const override { return 8; }

      Key_Length_Specification key_spec() const override
         {
         return m_key_spec;
         }

      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         verify_key_set(m_key_set);

         const size_t max_blocks_per_req = m_socket.max_bytes_per_request() / m_block_size;

         uint8_t hdr_buf[128] = { 0 };

         while(blocks)
            {
            const size_t to_proc = std::min(blocks, max_blocks_per_req);

            m_socket.read_data(out, to_proc * m_block_size);

            blocks -= to_proc;
            in += to_proc * m_block_size;
            out += to_proc * m_block_size;
            }
         }

      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         verify_key_set(m_key_set);
         // TODO must limit to at most 16 pages
         }

      void key_schedule(const uint8_t key[], size_t key_len)
         {
         m_key_set = false;

         // might throw:
         m_socket.set_key(key, key_len);

         m_key_set = true;
         }

      void clear() override
         {
         m_key_set = false;
         }

      BlockCipher* clone() const override
         {
         return new AF_Alg_Block_Cipher(m_lib_name, m_kernel_name, m_block_size, m_key_spec);
         }


   private:
      std::string m_lib_name;
      std::string m_kernel_name;
      size_t m_block_size;
      Key_Length_Specification m_key_spec;
      AF_Alg_Socket m_socket;

      bool m_key_set;
   };

}

std::unique_ptr<BlockCipher> create_af_alg_block_cipher(const std::string& name)
   {
   if(name == "AES-128")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(aes)", 16, Key_Length_Specification(16)));
   if(name == "AES-192")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(aes)", 16, Key_Length_Specification(24)));
   if(name == "AES-256")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(aes)", 16, Key_Length_Specification(32)));

   if(name == "Serpent")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(serpent)", 16, Key_Length_Specification(16, 32, 8)));


   return nullptr;
   }


}
