/*
 * (C) 2020 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SKEIN_512_MAC_H_
#define BOTAN_SKEIN_512_MAC_H_

#include <botan/mac.h>

namespace Botan {

class Skein_512;

/**
* The keyed variant of Skein-512
*/
class Skein_512_MAC final : public MessageAuthenticationCode
   {
   public:
      void clear() override;
      std::string name() const override;
      size_t output_length() const override;
      MessageAuthenticationCode* clone() const override;

      Key_Length_Specification key_spec() const override;

      Skein_512(size_t output_bits = 512,
                const std::string& personalization = "");

      Skein_512_MAC(const Skein_512_MAC&) = delete;
      Skein_512_MAC& operator=(const Skein_512_MAC&) = delete;

      ~Skein_512_MAC();

   private:
      void add_data(const uint8_t[], size_t) override;
      void final_result(uint8_t[]) override;
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;
      void key_schedule(const uint8_t key[], size_t size) override;

      std::unique_ptr<Skein_512> m_skein;
      secure_vector<uint8_t> m_key;
   };

}

#endif
