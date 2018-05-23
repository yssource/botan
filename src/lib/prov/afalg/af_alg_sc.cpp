/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/af_alg_prov.h>
#include <botan/stream_cipher.h>
#include <botan/exceptn.h>

#include <kcapi.h>

namespace Botan {

namespace {

class AF_Alg_Stream_Cipher final : public StreamCipher
   {
   public:
      AF_Alg_Stream_Cipher(const std::string& lib_name,
                           const std::string& kernel_name,
                           size_t iv_len,
                           const Key_Length_Specification& key_spec) :
         m_lib_name(lib_name),
         m_kernel_name(kernel_name),
         m_iv_len(iv_len),
         m_key_spec(key_spec),
         m_key_set(false)
         {
         }

      ~AF_Alg_Stream_Cipher() { clear(); }

      std::string name() const override { return m_lib_name; }

      std::string provider() const override { return "af_alg"; }

      Key_Length_Specification key_spec() const override
         {
         return m_key_spec;
         }

      void cipher(const uint8_t in[], uint8_t out[], size_t len) override
         {
         verify_key_set(m_key_set);

         int32_t rc = ::kcapi_cipher_encrypt(m_handle,
                                             in, len,
                                             (m_iv.size() > 0 ? m_iv.data() : nullptr),
                                             out, len,
                                             KCAPI_ACCESS_HEURISTIC);

         if(rc < 0)
            throw Exception("kcapi_cipher_encrypt failed");

         if(static_cast<size_t>(rc) != len)
            throw Exception("kcapi_cipher_encrypt incomplete encryption");
         }

      void seek(uint64_t) override
         {
         throw Not_Implemented("AF_ALG stream ciphers do not support seek");
         }

      void set_iv(const uint8_t iv[], size_t length)
         {
         if(!valid_iv_length(length))
            throw Invalid_IV_Length(name(), length);

         m_iv.resize(m_iv_len);
         zeroise(m_iv);
         buffer_insert(m_iv, 0, iv, length);
         }

      bool valid_iv_length(size_t iv_len) const override
         {
         return (iv_len <= m_iv_len);
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

      StreamCipher* clone() const override
         {
         return new AF_Alg_Stream_Cipher(m_lib_name, m_kernel_name, m_iv_len, m_key_spec);
         }

   private:
      std::string m_lib_name;
      std::string m_kernel_name;
      size_t m_iv_len;
      Key_Length_Specification m_key_spec;
      bool m_key_set;
      std::vector<uint8_t> m_iv;

      struct kcapi_handle* m_handle;
   };

}

std::unique_ptr<StreamCipher> create_af_alg_ctr_mode(const std::string& name)
   {
   const std::string ctr_name = "CTR-BE(" + name + ")";

   if(name == "AES-128")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(aes)", 16, Key_Length_Specification(16)));
   if(name == "AES-192")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(aes)", 16, Key_Length_Specification(24)));
   if(name == "AES-256")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(aes)", 16, Key_Length_Specification(32)));

   if(name == "Camellia-128")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(camellia)", 16, Key_Length_Specification(16)));
   if(name == "Camellia-192")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(camellia)", 16, Key_Length_Specification(24)));
   if(name == "Camellia-256")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(camellia)", 16, Key_Length_Specification(32)));

   if(name == "Serpent")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(serpent)", 16, Key_Length_Specification(16, 32, 8)));

   if(name == "Twofish")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(twofish)", 16, Key_Length_Specification(16, 32, 8)));

   if(name == "Blowfish")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(blowfish)", 8, Key_Length_Specification(4, 56, 1)));

   if(name == "CAST-128")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(cast5)", 8, Key_Length_Specification(16)));

   if(name == "DES")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(des)", 8, Key_Length_Specification(8)));

   if(name == "TripleDES" || name == "3DES")
      return std::unique_ptr<StreamCipher>(new AF_Alg_Stream_Cipher(ctr_name, "ctr(des3_ede)", 8, Key_Length_Specification(24)));

   return nullptr;
   }


}
