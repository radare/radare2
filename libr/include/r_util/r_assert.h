#ifndef R_ASSERT_H
#define R_ASSERT_H

#if defined (__GNUC__) && defined (__cplusplus)
#define R_STRFUNC     ((const char*) (__PRETTY_FUNCTION__))
#elif defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define R_STRFUNC     ((const char*) (__func__))
#elif defined (__GNUC__) || (defined(_MSC_VER) && (_MSC_VER > 1300))
#define R_STRFUNC     ((const char*) (__FUNCTION__))
#else
#define R_STRFUNC     ((const char*) ("???"))
#endif

typedef enum r_log_level {
	R_LOG_DEBUG = 0,
	R_LOG_INFO,
	R_LOG_WARNING,
	R_LOG_ERROR,
	R_LOG_CRITICAL
} RLogLevel;

R_API void r_log(RLogLevel level, const char *fmt, ...);

#define r_warn_if_reached()						\
	do {								\
		r_log (R_LOG_WARNING, "(%s:%d):%s%s code should not be reached\n", \
		       __FILE__, __LINE__, R_STRFUNC, R_STRFUNC[0] ? ":" : "");	\
	} while (0)

#define r_warn_if_fail(expr)					\
	do {								\
		if (!(expr)) {						\
			r_log (R_LOG_WARNING, "WARNING (%s:%d):%s%s runtime check failed: (%s)\n", \
			       __FILE__, __LINE__, R_STRFUNC, , R_STRFUNC[0] ? ":" : "", #expr); \
		}							\
	} while (0)

#ifdef R_DISABLE_CHECKS

#define r_return_if_fail(expr) do { (void) 0; } while (0)
#define r_return_val_if_fail(expr, val) do { (void) 0; } while (0)
#define r_return_if_reached() do { return; } while (0)
#define r_return_val_if_reached(val) do { return (val); } while (0)

#else // R_DISABLE_CHECKS

/**
 * r_return_if_fail:
 * @expr: the expression to check
 *
 * Verifies that the expression @expr, usually representing a precondition,
 * evaluates to `true`. If the function returns a value, use
 * r_return_val_if_fail() instead.
 *
 * If @expr evaluates to %FALSE, the current function should be considered to
 * have undefined behaviour (a programmer error). The only correct solution
 * to such an error is to change the module that is calling the current
 * function, so that it avoids this incorrect call.
 *
 * To make this undefined behaviour visible, if @expr evaluates to %FALSE,
 * the result is usually that a critical message is logged and the current
 * function returns.
 *
 * If `G_DISABLE_CHECKS` is defined then the check is not performed.  You
 * should therefore not depend on any side effects of @expr.
 */
#define r_return_if_fail(expr)						\
	do {								\
		if (!(expr)) {						\
			r_log (R_LOG_WARNING, "%s: assertion '%s' failed\n", R_STRFUNC, #expr); \
			return;						\
		}							\
	} while (0)

#define r_return_val_if_fail(expr, val)				\
	do {							\
		if (!(expr)) {					\
			r_log (R_LOG_WARNING, "%s: assertion '%s' failed\n", R_STRFUNC, #expr); \
			return (val);				\
		}						\
	} while (0)

#define r_return_if_reached()						\
	do {								\
		r_log (R_LOG_CRITICAL, "file %s: line %d (%s): should not be reached\n", __FILE__, __LINE, R_STRFUNC); \
		return;							\
	} while (0)

#define r_return_val_if_reached(val)					\
	do {								\
		r_log (R_LOG_CRITICAL, "file %s: line %d (%s): should not be reached\n", __FILE__, __LINE, R_STRFUNC); \
		return (val);						\
	} while (0)

#endif // R_DISABLE_CHECKS

#endif
