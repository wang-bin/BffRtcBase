#if (__ANDROID__ + 0)
#include "FileLogger.hpp"
#include "JMIUtils.hpp"

namespace jmi {

JMI_DEFINE(void, FileLogger::onLog, JMI_ARG3(const std::string&, jint, const std::string&))

} // namespace jmi
#endif // __ANDROID__
