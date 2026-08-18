#pragma once
/*
public class Object {
    public String toString();
}
*/
#include "jmi.h"

namespace jmi {
namespace java {
namespace lang {

class Object : public jmi::JObject<Object> {
public:
    using Base = jmi::JObject<Object>;
    using Base::Base;
    static constexpr auto name() { return JMISTR("java/lang/Object"); }
    std::string toString() const;
};

} // namespace lang
} // namespace java
} // namespace jmi
