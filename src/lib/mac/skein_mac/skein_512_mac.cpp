/*
 * (C) 2020 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/skein_512_mac.h>
#include <botan/skein_512.h>

namespace Botan {

Skein_512_MAC::Skein_512(size_t output_bits,
                         const std::string& personalization)
   {
   m_skein.reset(new Skein_512(output_bits, personalization);
   }

Skein_512_MAC::~Skein_512_MAC()
   {
   /* for ~unique_ptr */
   }

void Skein_512_MAC::clear()
   {
   m_key.clear();
   m_skein->clear();
   }

std::string Skein_512_MAC::name() const
   {
   return "Skein-512-MAC";
   }

size_t Skein_512_MAC::output_length() const
   {
   return m_skein->output_length();
   }

MessageAuthenticationCode* Skein_512_MAC::clone() const
   {
   return std::unique_ptr<MessageAuthenticationCode>(
      new Skein_512_MAC(m_skein->output_length() * 8, m_skein->personalization()));
   }

Key_Length_Specification Skein_512_MAC::key_spec() const
   {
   return Key_Length_Specification(1, 64);
   }

void Skein_512_MAC::add_data(const uint8_t[], size_t)
   {
   }

void Skein_512_MAC::final_result(uint8_t[])
   {
   }

void Skein_512_MAC::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   }

void Skein_512_MAC::key_schedule(const uint8_t key[], size_t size)
   {
   m_key.assign(key, key + size);
   }

}
