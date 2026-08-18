#pragma once
/*
public final class Integer extends Number implements Comparable<Integer> {
    public Integer(int value);
    public int intValue();
}
*/
#include "java.lang.Object.hpp"

namespace jmi {
namespace java {
namespace lang {

class Integer final : public jmi::JObject<Integer> {
public:
    using Base = jmi::JObject<Integer>;
    using Base::Base;
    static constexpr auto name() { return JMISTR("java/lang/Integer"); }
    jint intValue() const;
};

} // namespace lang
} // namespace java
} // namespace jmi
