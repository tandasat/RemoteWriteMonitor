//
// N4189: Scoped Resource - Generic RAII Wrapper for the Standard Library
// Peter Sommerlad and Andrew L. Sandoval
//
#ifndef SCOPE_EXIT_H_
#define SCOPE_EXIT_H_
#ifndef _MSC_VER
#define SCOPE_GUARD_NOEXCEPT(...) noexpect(__VA_ARGS__)
#else
#define SCOPE_GUARD_NOEXCEPT(...) 
#endif
#if _HAS_EXCEPTIONS
#define SCOPE_GUARD_TRY_BEGIN   try {
#define SCOPE_GUARD_CATCH_ALL   } catch (...) {
#define SCOPE_GUARD_CATCH_END   }
#else
#define SCOPE_GUARD_TRY_BEGIN   {{
#define SCOPE_GUARD_CATCH_ALL       \
    __pragma(warning(push))         \
    __pragma(warning(disable:4127)) \
                } if (0) {          \
    __pragma(warning(pop))
#define SCOPE_GUARD_CATCH_END   }}
#endif

// modeled slightly after Andrescu’s talk and article(s)
namespace std {
    namespace experimental {
        template <typename EF>
        struct scope_exit
        {
            // construction
            explicit
                scope_exit(EF &&f) SCOPE_GUARD_NOEXCEPT()
                : exit_function(std::move(f))
                , execute_on_destruction{ true }
            {
            }
            // move
            scope_exit(scope_exit &&rhs) SCOPE_GUARD_NOEXCEPT()
                : exit_function(std::move(rhs.exit_function))
                , execute_on_destruction{ rhs.execute_on_destruction }
            {
                rhs.release();
            }
            // release
            ~scope_exit() SCOPE_GUARD_NOEXCEPT(noexcept(this->exit_function()))
            {
                if (execute_on_destruction)
                    this->exit_function();
            }
            void release() SCOPE_GUARD_NOEXCEPT()
            {
                this->execute_on_destruction = false;
            }
        private:
            scope_exit(scope_exit const &) = delete;
            void operator=(scope_exit const &) = delete;
            scope_exit& operator=(scope_exit &&) = delete;
            EF exit_function;
            bool execute_on_destruction; // exposition only
        };
        template <typename EF>
        auto make_scope_exit(EF &&exit_function) -> decltype(scope_exit<std::remove_reference_t<EF>>(std::forward<EF>(exit_function))) SCOPE_GUARD_NOEXCEPT()
        {
            return scope_exit<std::remove_reference_t<EF>>(std::forward<EF>(exit_function));
        }
    }
}

#undef SCOPE_GUARD_TRY_BEGIN
#undef SCOPE_GUARD_CATCH_ALL
#undef SCOPE_GUARD_CATCH_END
#undef SCOPE_GUARD_NOEXCEPT
#endif /* SCOPE_EXIT_H_ */