#pragma once
/*
public class Pair<F, S> {
    public F first;
    public S second;
    public Pair(F first, S second);
}
*/
#include "JMIUtils.hpp"
#include "java.lang.Integer.hpp"
#include "java.lang.Object.hpp"

namespace jmi {
namespace android {
namespace util {

class Pair final : public jmi::JObject<Pair> {
public:
    using Base = jmi::JObject<Pair>;
    using Base::Base;
    static constexpr auto name() { return JMISTR("android/util/Pair"); }

    JMI_DEFINE_FIELD_CONST(java::lang::Object, first)
    JMI_DEFINE_FIELD_CONST(java::lang::Object, second)

    static Pair of(const std::string &first, jint second) {
        java::lang::Object key(jmi::from_string(first), true);
        java::lang::Integer value;
        value.create(second);
        Pair pair;
        pair.create(key, java::lang::Object(value.id(), false));
        return pair;
    }
};

} // namespace util
} // namespace android
} // namespace jmi
