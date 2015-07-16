//
// N4189: Scoped Resource - Generic RAII Wrapper for the Standard Library
// Peter Sommerlad and Andrew L. Sandoval
//
#ifndef UNIQUE_RESOURCE_H_
#define UNIQUE_RESOURCE_H_

#include <type_traits>

#ifndef _MSC_VER
#define UNIQUE_RESOURCE_NOEXCEPT(...) noexpect(__VA_ARGS__)
#else
#define UNIQUE_RESOURCE_NOEXCEPT(...) 
#endif
#if _HAS_EXCEPTIONS
#define UNIQUE_RESOURCE_TRY_BEGIN   try {
#define UNIQUE_RESOURCE_CATCH_ALL   } catch (...) {
#define UNIQUE_RESOURCE_CATCH_END   }
#else
#define UNIQUE_RESOURCE_TRY_BEGIN   {{
#define UNIQUE_RESOURCE_CATCH_ALL   \
    __pragma(warning(push))         \
    __pragma(warning(disable:4127)) \
                } if (0) {                      \
    __pragma(warning(pop))
#define UNIQUE_RESOURCE_CATCH_END   }}
#endif

namespace std {
    namespace experimental {
        template<typename R, typename D>
        class unique_resource
        {
            R resource;
            D deleter;
            bool execute_on_destruction; // exposition only
            unique_resource& operator=(unique_resource const &) = delete;
            unique_resource(unique_resource const &) = delete; // no copies!
        public:
            // construction
            explicit
                unique_resource(R && resource, D && deleter, bool shouldrun = true) UNIQUE_RESOURCE_NOEXCEPT()
                : resource(std::move(resource))
                , deleter(std::move(deleter))
                , execute_on_destruction{ shouldrun }
            {
            }
            // move
            unique_resource(unique_resource &&other) UNIQUE_RESOURCE_NOEXCEPT()
                : resource(std::move(other.resource))
                , deleter(std::move(other.deleter))
                , execute_on_destruction{ other.execute_on_destruction }
            {
                other.release();
            }
            unique_resource&
                operator=(unique_resource &&other) UNIQUE_RESOURCE_NOEXCEPT(noexcept(this->reset()))
            {
                this->reset();
                this->deleter = std::move(other.deleter);
                this->resource = std::move(other.resource);
                this->execute_on_destruction = other.execute_on_destruction;
                other.release();
                return *this;
            }
            // resource release
            ~unique_resource() UNIQUE_RESOURCE_NOEXCEPT(noexcept(this->reset()))
            {
                this->reset();

            }
            void reset() UNIQUE_RESOURCE_NOEXCEPT(noexcept(this->get_deleter()(resource)))
            {
                if (execute_on_destruction)
                {
                    this->execute_on_destruction = false;
                    this->get_deleter()(resource);
                }
            }
            void reset(R && newresource) UNIQUE_RESOURCE_NOEXCEPT(noexcept(this->reset()))
            {
                this->reset();
                this->resource = std::move(newresource);
                this->execute_on_destruction = true;
            }
            R const & release() UNIQUE_RESOURCE_NOEXCEPT()
            {
                this->execute_on_destruction = false;
                return this->get();
            }
            // resource access
            R const & get() const UNIQUE_RESOURCE_NOEXCEPT()
            {
                return this->resource;
            }
            operator R const &() const UNIQUE_RESOURCE_NOEXCEPT()
            {
                return this->resource;
            }
            R
                operator->() const UNIQUE_RESOURCE_NOEXCEPT()
            {
                return this->resource;
            }
            std::add_lvalue_reference_t <
                std::remove_pointer_t < R >>
                operator*() const
            {
                return *this->resource;
            }
            // deleter access
            const D &
                get_deleter() const UNIQUE_RESOURCE_NOEXCEPT()
            {
                return this->deleter;
            }
        };
        //factories
        template<typename R, typename D>
        auto
            make_unique_resource(R && r, D &&d) -> decltype(unique_resource<R, std::remove_reference_t<D>>(
            std::move(r)
            , std::forward<std::remove_reference_t<D>>(d)
            , true)) UNIQUE_RESOURCE_NOEXCEPT()
        {
            return unique_resource<R, std::remove_reference_t<D>>(
                std::move(r)
                , std::forward<std::remove_reference_t<D>>(d)
                , true);

        }
        template<typename R, typename D>
        auto
            make_unique_resource_checked(R r, R invalid, D d) -> decltype(unique_resource<R, D>(std::move(r), std::move(d), shouldrun)) UNIQUE_RESOURCE_NOEXCEPT()
        {
            bool shouldrun = not bool(r == invalid);
            return unique_resource<R, D>(std::move(r), std::move(d), shouldrun);
        }
    }
}


#undef UNIQUE_RESOURCE_TRY_BEGIN
#undef UNIQUE_RESOURCE_CATCH_ALL
#undef UNIQUE_RESOURCE_CATCH_END
#undef UNIQUE_RESOURCE_NOEXCEPT
#endif /* UNIQUE_RESOURCE_H_ */