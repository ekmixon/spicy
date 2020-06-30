// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace tuple {

template<typename Tuple, size_t Idx>
ptrdiff_t elementOffset() {
    // This is pretty certainly not well-defined, but seems to work for us ...
    const Tuple* p = nullptr;
    return reinterpret_cast<const char*>(&std::get<Idx>(*p)) - reinterpret_cast<const char*>(p);
}

} // namespace tuple

namespace detail::adl {
template<typename... Ts>
inline std::string to_string(const std::tuple<Ts...>& x, adl::tag /*unused*/) {
    auto y = rt::map_tuple(x, [&](auto& v) { return hilti::rt::to_string(v); });
    return fmt("(%s)", rt::join_tuple_for_print(std::move(y)));
}

template<typename... Ts>
inline std::string to_string_for_print(const std::tuple<Ts...>& x, adl::tag /*unused*/) {
    auto y = rt::map_tuple(x, [&](auto& v) { return hilti::rt::to_string(v); });
    return fmt("(%s)", rt::join_tuple_for_print(std::move(y)));
}
} // namespace detail::adl

} // namespace hilti::rt

namespace std {

template<typename... Ts>
inline std::ostream& operator<<(std::ostream& out, const std::tuple<Ts...>& x) {
    return out << hilti::rt::to_string_for_print(x);
}

} // namespace std
