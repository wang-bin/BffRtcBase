#include "QuicWebSocketClient.hpp"
#include "JMIUtils.hpp"

namespace jmi {

JMI_DEFINE(void, QuicWebSocketClient::dispatchOpen, JMI_ARG0())
JMI_DEFINE(void, QuicWebSocketClient::dispatchMessage, JMI_ARG2(const std::vector<jbyte>&, jboolean))
JMI_DEFINE(void, QuicWebSocketClient::dispatchClose, JMI_ARG3(jint, const std::string&, jboolean))
JMI_DEFINE(void, QuicWebSocketClient::dispatchError, JMI_ARG3(jint, jint, const std::string&))

} // namespace jmi
