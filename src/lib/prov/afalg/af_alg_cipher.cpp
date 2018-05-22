/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/af_alg_prov.h>
#include <botan/internal/af_alg_util.h>
#include <botan/cipher_mode.h>
#include <botan/exceptn.h>

namespace Botan {

#if 0
namespace {

class AF_Alg_Cipher_Mode : public Cipher_Mode
   {
   public:
      AF_Alg_Cipher_Mode(const std::string& lib_name,
                         const std::string& kernel_name) :
         m_lib_name(lib_name),
         m_kernel_name(kernel_name),
         m_socket("skcipher", kernel_name)
         {}

      std::string name() const override { return m_lib_name; }

      void start_msg(const uint8_t iv[], size_t iv_len) override
         {}

      void reset() override
         {
         }

      void clear() override
         {
         }

      size_t default_nonce_length() const override
         {
         }

      bool valid_nonce_length() const override
         {

         }

      size_t update_granularity() const override
         {

         }

      size_t minimum_final_size() const override
         {

         }

      void key_schedule(const uint8_t key[], size_t len)
         {
         }

      Key_Length_Specification key_spec() const override
         {
         }

   private:
      std::string m_lib_name;
      std::string m_kernel_name;
      AF_Alg_Socket m_socket;
   };

}
#endif

std::unique_ptr<Cipher_Mode> create_af_alg_cipher(const std::string& name)
   {
   /*
   if(name == "AES-128/CBC")
      return std::unique_ptr<Cipher_Mode>(new AF_Alg_Cipher_Mode(name, "cbc(aes)"));
   */
   return nullptr;
   }

}
