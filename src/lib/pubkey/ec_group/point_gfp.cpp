/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011,2012,2014,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/point_gfp.h>
#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/rounding.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

PointGFp::PointGFp(const CurveGFp& curve) :
   m_curve(curve),
   m_coord_x(0),
   m_coord_y(curve.get_1_rep()),
   m_coord_z(0)
   {
   // Assumes Montgomery rep of zero is zero
   }

PointGFp::PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y) :
   m_curve(curve),
   m_coord_x(x),
   m_coord_y(y),
   m_coord_z(m_curve.get_1_rep())
   {
   if(x <= 0 || x >= curve.get_p())
      throw Invalid_Argument("Invalid PointGFp affine x");
   if(y <= 0 || y >= curve.get_p())
      throw Invalid_Argument("Invalid PointGFp affine y");

   BigInt::Pool pool;
   m_curve.to_rep(m_coord_x, pool);
   m_curve.to_rep(m_coord_y, pool);
   }

void PointGFp::randomize_repr(RandomNumberGenerator& rng)
   {
   BigInt::Pool pool;
   randomize_repr(rng, pool);
   }

void PointGFp::randomize_repr(RandomNumberGenerator& rng, BigInt::Pool& pool)
   {
   const BigInt mask = BigInt::random_integer(rng, 2, m_curve.get_p());

   /*
   * No reason to convert this to Montgomery representation first,
   * just pretend the random mask was chosen as Redc(mask) and the
   * random mask we generated above is in the Montgomery
   * representation.
   * //m_curve.to_rep(mask, ws);
   */
   BigInt::Pool::Scope scope(pool);

   const BigInt mask2 = m_curve.sqr_to_tmp(mask, pool);
   const BigInt mask3 = m_curve.mul_to_tmp(mask2, mask, pool);

   m_coord_x = m_curve.mul_to_tmp(m_coord_x, mask2, pool);
   m_coord_y = m_curve.mul_to_tmp(m_coord_y, mask3, pool);
   m_coord_z = m_curve.mul_to_tmp(m_coord_z, mask, pool);
   }

namespace {

inline word all_zeros(const word x[], size_t len)
   {
   word z = 0;
   for(size_t i = 0; i != len; ++i)
      z |= x[i];
   return CT::Mask<word>::is_zero(z).value();
   }

}

void PointGFp::add_affine(const word x_words[], size_t x_size,
                          const word y_words[], size_t y_size,
                          BigInt::Pool& pool)
   {
   if(all_zeros(x_words, x_size) & all_zeros(y_words, y_size))
      {
      return;
      }

   if(is_zero())
      {
      m_coord_x.set_words(x_words, x_size);
      m_coord_y.set_words(y_words, y_size);
      m_coord_z = m_curve.get_1_rep();
      return;
      }

   BigInt::Pool::Scope scope(pool);

   secure_vector<word>& sub_ws = scope.get().get_word_vector();

   BigInt& T0 = scope.get();
   BigInt& T1 = scope.get();
   BigInt& T2 = scope.get();
   BigInt& T3 = scope.get();
   BigInt& T4 = scope.get();

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   simplified with Z2 = 1
   */

   const BigInt& p = m_curve.get_p();

   m_curve.sqr(T3, m_coord_z, pool); // z1^2
   m_curve.mul(T4, x_words, x_size, T3, pool); // x2*z1^2

   m_curve.mul(T2, m_coord_z, T3, pool); // z1^3
   m_curve.mul(T0, y_words, y_size, T2, pool); // y2*z1^3

   T4.mod_sub(m_coord_x, p, sub_ws); // x2*z1^2 - x1*z2^2

   T0.mod_sub(m_coord_y, p, sub_ws);

   if(T4.is_zero())
      {
      if(T0.is_zero())
         {
         mult2(pool);
         return;
         }

      // setting to zero:
      m_coord_x.clear();
      m_coord_y = m_curve.get_1_rep();
      m_coord_z.clear();
      return;
      }

   m_curve.sqr(T2, T4, pool);

   m_curve.mul(T3, m_coord_x, T2, pool);

   m_curve.mul(T1, T2, T4, pool);

   m_curve.sqr(m_coord_x, T0, pool);
   m_coord_x.mod_sub(T1, p, sub_ws);

   m_coord_x.mod_sub(T3, p, sub_ws);
   m_coord_x.mod_sub(T3, p, sub_ws);

   T3.mod_sub(m_coord_x, p, sub_ws);

   m_curve.mul(T2, T0, T3, pool);
   m_curve.mul(T0, m_coord_y, T1, pool);
   T2.mod_sub(T0, p, sub_ws);
   m_coord_y.swap(T2);

   m_curve.mul(T0, m_coord_z, T4, pool);
   m_coord_z.swap(T0);
   }

void PointGFp::add(const word x_words[], size_t x_size,
                   const word y_words[], size_t y_size,
                   const word z_words[], size_t z_size,
                   BigInt::Pool& pool)
   {
   if(all_zeros(x_words, x_size) & all_zeros(z_words, z_size))
      return;

   if(is_zero())
      {
      m_coord_x.set_words(x_words, x_size);
      m_coord_y.set_words(y_words, y_size);
      m_coord_z.set_words(z_words, z_size);
      return;
      }

   BigInt::Pool::Scope scope(pool);

   secure_vector<word>& sub_ws = scope.get().get_word_vector();

   BigInt& T0 = scope.get();
   BigInt& T1 = scope.get();
   BigInt& T2 = scope.get();
   BigInt& T3 = scope.get();
   BigInt& T4 = scope.get();
   BigInt& T5 = scope.get();

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   */

   const BigInt& p = m_curve.get_p();

   m_curve.sqr(T0, z_words, z_size, pool); // z2^2
   m_curve.mul(T1, m_coord_x, T0, pool); // x1*z2^2
   m_curve.mul(T3, z_words, z_size, T0, pool); // z2^3
   m_curve.mul(T2, m_coord_y, T3, pool); // y1*z2^3

   m_curve.sqr(T3, m_coord_z, pool); // z1^2
   m_curve.mul(T4, x_words, x_size, T3, pool); // x2*z1^2

   m_curve.mul(T5, m_coord_z, T3, pool); // z1^3
   m_curve.mul(T0, y_words, y_size, T5, pool); // y2*z1^3

   T4.mod_sub(T1, p, sub_ws); // x2*z1^2 - x1*z2^2

   T0.mod_sub(T2, p, sub_ws);

   if(T4.is_zero())
      {
      if(T0.is_zero())
         {
         mult2(pool);
         return;
         }

      // setting to zero:
      m_coord_x.clear();
      m_coord_y = m_curve.get_1_rep();
      m_coord_z.clear();
      return;
      }

   m_curve.sqr(T5, T4, pool);

   m_curve.mul(T3, T1, T5, pool);

   m_curve.mul(T1, T5, T4, pool);

   m_curve.sqr(m_coord_x, T0, pool);
   m_coord_x.mod_sub(T1, p, sub_ws);
   m_coord_x.mod_sub(T3, p, sub_ws);
   m_coord_x.mod_sub(T3, p, sub_ws);

   T3.mod_sub(m_coord_x, p, sub_ws);

   m_curve.mul(m_coord_y, T0, T3, pool);
   m_curve.mul(T3, T2, T1, pool);

   m_coord_y.mod_sub(T3, p, sub_ws);

   m_curve.mul(T3, z_words, z_size, m_coord_z, pool);
   m_curve.mul(m_coord_z, T3, T4, pool);
   }

void PointGFp::mult2i(size_t iterations, BigInt::Pool& pool)
   {
   if(iterations == 0)
      return;

   if(m_coord_y.is_zero())
      {
      *this = PointGFp(m_curve); // setting myself to zero
      return;
      }

   /*
   TODO we can save 2 squarings per iteration by computing
   a*Z^4 using values cached from previous iteration
   */
   for(size_t i = 0; i != iterations; ++i)
      mult2(pool);
   }

// *this *= 2
void PointGFp::mult2(BigInt::Pool& pool)
   {
   if(is_zero())
      return;

   if(m_coord_y.is_zero())
      {
      *this = PointGFp(m_curve); // setting myself to zero
      return;
      }

   BigInt::Pool::Scope scope(pool);

   secure_vector<word>& sub_ws = scope.get().get_word_vector();

   BigInt& T0 = scope.get();
   BigInt& T1 = scope.get();
   BigInt& T2 = scope.get();
   BigInt& T3 = scope.get();
   BigInt& T4 = scope.get();

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
   */
   const BigInt& p = m_curve.get_p();

   m_curve.sqr(T0, m_coord_y, pool);

   m_curve.mul(T1, m_coord_x, T0, pool);
   T1.mod_mul(4, p, sub_ws);

   if(m_curve.a_is_zero())
      {
      // if a == 0 then 3*x^2 + a*z^4 is just 3*x^2
      m_curve.sqr(T4, m_coord_x, pool); // x^2
      T4.mod_mul(3, p, sub_ws); // 3*x^2
      }
   else if(m_curve.a_is_minus_3())
      {
      /*
      if a == -3 then
        3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)
      */
      m_curve.sqr(T3, m_coord_z, pool); // z^2

      // (x-z^2)
      T2 = m_coord_x;
      T2.mod_sub(T3, p, sub_ws);

      // (x+z^2)
      T3.mod_add(m_coord_x, p, sub_ws);

      m_curve.mul(T4, T2, T3, pool); // (x-z^2)*(x+z^2)

      T4.mod_mul(3, p, sub_ws); // 3*(x-z^2)*(x+z^2)
      }
   else
      {
      m_curve.sqr(T3, m_coord_z, pool); // z^2
      m_curve.sqr(T4, T3, pool); // z^4
      m_curve.mul(T3, m_curve.get_a_rep(), T4, pool); // a*z^4

      m_curve.sqr(T4, m_coord_x, pool); // x^2
      T4.mod_mul(3, p, sub_ws);
      T4.mod_add(T3, p, sub_ws); // 3*x^2 + a*z^4
      }

   m_curve.sqr(T2, T4, pool);
   T2.mod_sub(T1, p, sub_ws);
   T2.mod_sub(T1, p, sub_ws);

   m_curve.sqr(T3, T0, pool);
   T3.mod_mul(8, p, sub_ws);

   T1.mod_sub(T2, p, sub_ws);

   m_curve.mul(T0, T4, T1, pool);
   T0.mod_sub(T3, p, sub_ws);

   m_coord_x.swap(T2);

   m_curve.mul(T2, m_coord_y, m_coord_z, pool);
   T2.mod_mul(2, p, sub_ws);

   m_coord_y.swap(T0);
   m_coord_z.swap(T2);
   }

// arithmetic operators
PointGFp& PointGFp::operator+=(const PointGFp& rhs)
   {
   BigInt::Pool pool;
   add(rhs, pool);
   return *this;
   }

PointGFp& PointGFp::operator-=(const PointGFp& rhs)
   {
   PointGFp minus_rhs = PointGFp(rhs).negate();

   if(is_zero())
      *this = minus_rhs;
   else
      *this += minus_rhs;

   return *this;
   }

PointGFp& PointGFp::operator*=(const BigInt& scalar)
   {
   *this = scalar * *this;
   return *this;
   }

PointGFp operator*(const BigInt& scalar, const PointGFp& point)
   {
   BOTAN_DEBUG_ASSERT(point.on_the_curve());

   const size_t scalar_bits = scalar.bits();

   BigInt::Pool pool;

   PointGFp R[2] = { point.zero(), point };

   for(size_t i = scalar_bits; i > 0; i--)
      {
      const size_t b = scalar.get_bit(i - 1);
      R[b ^ 1].add(R[b], pool);
      R[b].mult2(pool);
      }

   if(scalar.is_negative())
      R[0].negate();

   BOTAN_DEBUG_ASSERT(R[0].on_the_curve());

   return R[0];
   }

//static
void PointGFp::force_all_affine(std::vector<PointGFp>& points,
                                BigInt::Pool& pool)
   {
   if(points.size() <= 1)
      {
      for(size_t i = 0; i != points.size(); ++i)
         points[i].force_affine();
      return;
      }

   /*
   For >= 2 points use Montgomery's trick

   See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
   (Hankerson, Menezes, Vanstone)

   TODO is it really necessary to save all k points in c?
   */

   BigInt::Pool::Scope scope(pool);

   const CurveGFp& curve = points[0].m_curve;
   const BigInt& rep_1 = curve.get_1_rep();

   std::vector<BigInt*> c;
   c.push_back(&points[0].m_coord_z);

   for(size_t i = 1; i != points.size(); ++i)
      {
      c.push_back(&scope.get());
      curve.mul(*c[i], *c[i-1], points[i].m_coord_z, pool);
      }

   BigInt s_inv = curve.invert_element(*c[c.size()-1], pool);

   BigInt& z_inv = scope.get();
   BigInt& z2_inv = scope.get();
   BigInt& z3_inv = scope.get();

   for(size_t i = points.size() - 1; i != 0; i--)
      {
      PointGFp& point = points[i];

      curve.mul(z_inv, s_inv, *c[i-1], pool);

      s_inv = curve.mul_to_tmp(s_inv, point.m_coord_z, pool);

      curve.sqr(z2_inv, z_inv, pool);
      curve.mul(z3_inv, z2_inv, z_inv, pool);
      point.m_coord_x = curve.mul_to_tmp(point.m_coord_x, z2_inv, pool);
      point.m_coord_y = curve.mul_to_tmp(point.m_coord_y, z3_inv, pool);
      point.m_coord_z = rep_1;
      }

   curve.sqr(z2_inv, s_inv, pool);
   curve.mul(z3_inv, z2_inv, s_inv, pool);
   points[0].m_coord_x = curve.mul_to_tmp(points[0].m_coord_x, z2_inv, pool);
   points[0].m_coord_y = curve.mul_to_tmp(points[0].m_coord_y, z3_inv, pool);
   points[0].m_coord_z = rep_1;
   }

void PointGFp::force_affine()
   {
   if(is_zero())
      throw Invalid_State("Cannot convert zero ECC point to affine");

   BigInt::Pool pool;
   const BigInt z_inv = m_curve.invert_element(m_coord_z, pool);
   const BigInt z2_inv = m_curve.sqr_to_tmp(z_inv, pool);
   const BigInt z3_inv = m_curve.mul_to_tmp(z_inv, z2_inv, pool);
   m_coord_x = m_curve.mul_to_tmp(m_coord_x, z2_inv, pool);
   m_coord_y = m_curve.mul_to_tmp(m_coord_y, z3_inv, pool);
   m_coord_z = m_curve.get_1_rep();
   }

bool PointGFp::is_affine() const
   {
   return m_curve.is_one(m_coord_z);
   }

BigInt PointGFp::get_affine_x(BigInt::Pool& pool) const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   if(is_affine())
      return m_curve.from_rep(m_coord_x, pool);

   BigInt::Pool::Scope scope(pool);
   BigInt& z2 = scope.get();
   m_curve.sqr(z2, m_coord_z, pool);
   z2 = m_curve.invert_element(z2, pool);

   BigInt r;
   m_curve.mul(r, m_coord_x, z2, pool);
   m_curve.from_rep(r, pool);
   return r;
   }

BigInt PointGFp::get_affine_y(BigInt::Pool& pool) const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   if(is_affine())
      return m_curve.from_rep(m_coord_y, pool);

   const BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, pool);
   const BigInt z3 = m_curve.mul_to_tmp(m_coord_z, z2, pool);
   const BigInt z3_inv = m_curve.invert_element(z3, pool);

   BigInt r;
   m_curve.mul(r, m_coord_y, z3_inv, pool);
   m_curve.from_rep(r, pool);
   return r;
   }

bool PointGFp::on_the_curve(BigInt::Pool& pool) const
   {
   /*
   Is the point still on the curve?? (If everything is correct, the
   point is always on its curve; then the function will return true.
   If somehow the state is corrupted, which suggests a fault attack
   (or internal computational error), then return false.
   */
   if(is_zero())
      return true;

   BigInt::Pool::Scope scope(pool);
   BigInt& y2 = scope.get();
   BigInt& x2 = scope.get();
   BigInt& x3 = scope.get();
   BigInt& ax = scope.get();
   BigInt& z2 = scope.get();

   m_curve.sqr(z2, m_coord_z, pool);

   m_curve.sqr(y2, m_coord_y, pool);
   m_curve.from_rep(y2, pool); // why??!

   m_curve.sqr(x2, m_coord_x, pool);
   m_curve.mul(x3, x2, m_coord_x, pool);
   m_curve.mul(ax, m_coord_x, m_curve.get_a_rep(), pool);

   if(m_coord_z == z2) // Is z equal to 1 (in Montgomery form)?
      {
      if(y2 != m_curve.from_rep(x3 + ax + m_curve.get_b_rep(), pool))
         return false;
      }

   BigInt& z3 = scope.get();
   BigInt& z4 = scope.get();
   BigInt& z6 = scope.get();
   BigInt& ax_z4 = scope.get();
   BigInt& b_z6 = scope.get();

   m_curve.mul(z3, z2, m_coord_z, pool);
   m_curve.sqr(z4, z2, pool);
   m_curve.sqr(z6, z3, pool);

   m_curve.mul(ax_z4, ax, z4, pool);
   m_curve.mul(b_z6, m_curve.get_b_rep(), z6, pool);

   if(y2 != m_curve.from_rep(x3 + ax_z4 + b_z6, pool))
      return false;

   return true;
   }

// swaps the states of *this and other, does not throw!
void PointGFp::swap(PointGFp& other)
   {
   m_curve.swap(other.m_curve);
   m_coord_x.swap(other.m_coord_x);
   m_coord_y.swap(other.m_coord_y);
   m_coord_z.swap(other.m_coord_z);
   }

bool PointGFp::operator==(const PointGFp& other) const
   {
   if(m_curve != other.m_curve)
      return false;

   // If this is zero, only equal if other is also zero
   if(is_zero())
      return other.is_zero();

   BigInt::Pool pool;
   return (get_affine_x(pool) == other.get_affine_x(pool) &&
           get_affine_y(pool) == other.get_affine_y(pool));
   }

// encoding and decoding
std::vector<uint8_t> PointGFp::encode(PointGFp::Compression_Type format) const
   {
   if(is_zero())
      return std::vector<uint8_t>(1); // single 0 byte

   const size_t p_bytes = m_curve.get_p().bytes();

   BigInt::Pool pool;
   const BigInt x = get_affine_x(pool);
   const BigInt y = get_affine_y(pool);

   std::vector<uint8_t> result;

   if(format == PointGFp::UNCOMPRESSED)
      {
      result.resize(1 + 2*p_bytes);
      result[0] = 0x04;
      BigInt::encode_1363(&result[1], p_bytes, x);
      BigInt::encode_1363(&result[1+p_bytes], p_bytes, y);
      }
   else if(format == PointGFp::COMPRESSED)
      {
      result.resize(1 + p_bytes);
      result[0] = 0x02 | static_cast<uint8_t>(y.get_bit(0));
      BigInt::encode_1363(&result[1], p_bytes, x);
      }
   else if(format == PointGFp::HYBRID)
      {
      result.resize(1 + 2*p_bytes);
      result[0] = 0x06 | static_cast<uint8_t>(y.get_bit(0));
      BigInt::encode_1363(&result[1], p_bytes, x);
      BigInt::encode_1363(&result[1+p_bytes], p_bytes, y);
      }
   else
      throw Invalid_Argument("EC2OSP illegal point encoding");

   return result;
   }

namespace {

BigInt decompress_point(bool yMod2,
                        const BigInt& x,
                        const BigInt& curve_p,
                        const BigInt& curve_a,
                        const BigInt& curve_b)
   {
   BigInt xpow3 = x * x * x;

   BigInt g = curve_a * x;
   g += xpow3;
   g += curve_b;
   g = g % curve_p;

   BigInt z = ressol(g, curve_p);

   if(z < 0)
      throw Illegal_Point("error during EC point decompression");

   if(z.get_bit(0) != yMod2)
      z = curve_p - z;

   return z;
   }

}

PointGFp OS2ECP(const uint8_t data[], size_t data_len,
                const CurveGFp& curve)
   {
   // Should we really be doing this?
   if(data_len <= 1)
      return PointGFp(curve); // return zero

   std::pair<BigInt, BigInt> xy = OS2ECP(data, data_len, curve.get_p(), curve.get_a(), curve.get_b());

   PointGFp point(curve, xy.first, xy.second);

   if(!point.on_the_curve())
      throw Illegal_Point("OS2ECP: Decoded point was not on the curve");

   return point;
   }

std::pair<BigInt, BigInt> OS2ECP(const uint8_t data[], size_t data_len,
                                 const BigInt& curve_p,
                                 const BigInt& curve_a,
                                 const BigInt& curve_b)
   {
   if(data_len <= 1)
      throw Decoding_Error("OS2ECP invalid point");

   const uint8_t pc = data[0];

   BigInt x, y;

   if(pc == 2 || pc == 3)
      {
      //compressed form
      x = BigInt::decode(&data[1], data_len - 1);

      const bool y_mod_2 = ((pc & 0x01) == 1);
      y = decompress_point(y_mod_2, x, curve_p, curve_a, curve_b);
      }
   else if(pc == 4)
      {
      const size_t l = (data_len - 1) / 2;

      // uncompressed form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l+1], l);
      }
   else if(pc == 6 || pc == 7)
      {
      const size_t l = (data_len - 1) / 2;

      // hybrid form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l+1], l);

      const bool y_mod_2 = ((pc & 0x01) == 1);

      if(decompress_point(y_mod_2, x, curve_p, curve_a, curve_b) != y)
         throw Illegal_Point("OS2ECP: Decoding error in hybrid format");
      }
   else
      throw Invalid_Argument("OS2ECP: Unknown format type " + std::to_string(pc));

   return std::make_pair(x, y);
   }

}
