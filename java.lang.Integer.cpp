#if (__ANDROID__ + 0)
#include "java.lang.Integer.hpp"
#include "JMIUtils.hpp"

namespace jmi {
namespace java {
namespace lang {

JMI_DEFINE_CONST(jint, Integer::intValue, JMI_ARG0())

} // namespace lang
} // namespace java
} // namespace jmi
#endif // __ANDROID__
