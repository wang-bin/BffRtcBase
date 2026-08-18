#if (__ANDROID__ + 0)
#include "java.lang.Object.hpp"
#include "JMIUtils.hpp"

namespace jmi {
namespace java {
namespace lang {

JMI_DEFINE_CONST(std::string, Object::toString, JMI_ARG0())

} // namespace lang
} // namespace java
} // namespace jmi
#endif // __ANDROID__
