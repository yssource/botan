/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OBJ_POOL_H_
#define BOTAN_OBJ_POOL_H_

#include <botan/assert.h>
#include <deque>
#include <vector>

namespace Botan {

template<typename T>
class ObjPool
   {
   public:
      ObjPool() : m_used(0)
         {
         }

      class Scope
         {
         public:
            Scope(ObjPool& pool) : m_pool(pool)
               {
               m_pool.enter_scope();
               }

            T& get() { return m_pool.get(); }

            ~Scope() { m_pool.exit_scope(); }

         private:
            ObjPool& m_pool;
         };

   private:
      friend class ObjPool<T>::Scope;

      void enter_scope()
         {
         m_scopes.push_back(m_used);
         }

      T& get()
         {
         if(m_used == m_pool.size())
            {
            m_pool.emplace_back();
            }

         T& r = m_pool[m_used];
         m_used += 1;
         return r;
         }

      void exit_scope()
         {
         BOTAN_STATE_CHECK(m_scopes.empty() == false);

         size_t scope_mark = m_scopes[m_scopes.size()-1];
         m_scopes.pop_back();
         m_used = scope_mark;
         }

      std::deque<T> m_pool;
      std::vector<size_t> m_scopes;
      size_t m_used;
   };

}

#endif
