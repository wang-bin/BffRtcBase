#if (__ANDROID__ + 0)
#include "CurlWebSocketClient.hpp"
#include "JMIUtils.hpp"

namespace jmi {

JMI_DEFINE(void, CurlWebSocketClient::dispatchOpen, JMI_ARG0())
JMI_DEFINE(void, CurlWebSocketClient::dispatchMessage, JMI_ARG2(const std::vector<jbyte>&, jboolean))
JMI_DEFINE(void, CurlWebSocketClient::dispatchClose, JMI_ARG3(jint, const std::string&, jboolean))
JMI_DEFINE(void, CurlWebSocketClient::dispatchError, JMI_ARG3(jint, jint, const std::string&))

} // namespace jmi
#endif // __ANDROID__
