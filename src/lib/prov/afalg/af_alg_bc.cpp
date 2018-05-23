/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/af_alg_prov.h>
#include <botan/block_cipher.h>
#include <botan/exceptn.h>

#include <kcapi.h>

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
         m_key_set(false)
         {
         }

      ~AF_Alg_Block_Cipher() { clear(); }

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

         const size_t bytes = blocks * m_block_size;

         int32_t rc = ::kcapi_cipher_encrypt(m_handle,
                                             in, bytes,
                                             nullptr,
                                             out, bytes,
                                             KCAPI_ACCESS_HEURISTIC);

         if(rc < 0)
            throw Exception("kcapi_cipher_encrypt failed");

         if(static_cast<size_t>(rc) != bytes)
            throw Exception("kcapi_cipher_encrypt incomplete encryption");
         }

      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         verify_key_set(m_key_set);

         const size_t bytes = blocks * m_block_size;

         int32_t rc = ::kcapi_cipher_decrypt(m_handle,
                                             in, bytes,
                                             nullptr,
                                             out, bytes,
                                             KCAPI_ACCESS_HEURISTIC);

         if(rc < 0)
            throw Exception("kcapi_cipher_decrypt failed");

         if(static_cast<size_t>(rc) != blocks*m_block_size)
            throw Exception("kcapi_cipher_decrypt incomplete decryption");
         }

      void key_schedule(const uint8_t key[], size_t key_len)
         {
         clear();

         if(::kcapi_cipher_init(&m_handle, m_kernel_name.c_str(), 0) != 0)
            throw Exception("kcapi_cipher_init failed");

         int rc = ::kcapi_cipher_setkey(m_handle, key, key_len);

         if(rc < 0)
            throw Exception("kcapi_cipher_setkey failed");

         m_key_set = true;
         }

      void clear() override
         {
         if(m_key_set)
            {
            ::kcapi_cipher_destroy(m_handle);
            m_key_set = false;
            }
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
      bool m_key_set;

      struct kcapi_handle* m_handle;
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

   if(name == "Camellia-128")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(camellia)", 16, Key_Length_Specification(16)));
   if(name == "Camellia-192")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(camellia)", 16, Key_Length_Specification(24)));
   if(name == "Camellia-256")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(camellia)", 16, Key_Length_Specification(32)));

   if(name == "Serpent")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(serpent)", 16, Key_Length_Specification(16, 32, 8)));

   if(name == "Twofish")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(twofish)", 16, Key_Length_Specification(16, 32, 8)));

   if(name == "Blowfish")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(blowfish)", 8, Key_Length_Specification(4, 56, 1)));

   if(name == "CAST-128")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(cast5)", 8, Key_Length_Specification(16)));

   if(name == "DES")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(des)", 8, Key_Length_Specification(8)));

   if(name == "TripleDES" || name == "3DES")
      return std::unique_ptr<BlockCipher>(new AF_Alg_Block_Cipher(name, "ecb(des3_ede)", 8, Key_Length_Specification(24)));

   return nullptr;
   }


}
