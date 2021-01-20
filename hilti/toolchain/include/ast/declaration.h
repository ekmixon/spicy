// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/base/type_erase.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Declaration` interface. */
class isDeclaration : public isNode {};
} // namespace trait

namespace declaration {

/** Linkage defining visibility/accessability of a declaration. */
enum class Linkage {
    Init,    /// executes automatically at startup, not otherwise accessible
    Struct,  /// method inside a method
    Private, /// accessible only locally
    Public,  /// accessible across modules
};

namespace detail {
constexpr util::enum_::Value<Linkage> linkages[] = {
    {Linkage::Struct, "method"},
    {Linkage::Public, "public"},
    {Linkage::Private, "private"},
    {Linkage::Init, "init"},
};
} // namespace detail

/** Returns the HILTI string representation corresponding to a linkage. */
constexpr auto to_string(Linkage f) { return util::enum_::to_string(f, detail::linkages); }

namespace linkage {
/**
 * Parses a HILTI string representation of a linkage.
 *
 * @exception `std::out_of_range` if the string does not map to a linkage
 */
constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Linkage>(s, detail::linkages); }
} // namespace linkage

namespace detail {

#include <hilti/autogen/__declaration.h>

/** Creates an AST node representing a `Declaration`. */
inline Node to_node(Declaration t) { return Node(std::move(t)); }

/** Renders a declaration as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Declaration d) { return out << to_node(std::move(d)); }

inline bool operator==(const Declaration& x, const Declaration& y) {
    if ( &x == &y )
        return true;

    assert(x.isEqual(y) == y.isEqual(x)); // Expected to be symmetric.
    return x.isEqual(y);
}

inline bool operator!=(const Declaration& d1, const Declaration& d2) { return ! (d1 == d2); }

} // namespace detail
} // namespace declaration

using Declaration = declaration::detail::Declaration;
using declaration::detail::to_node;

/** Constructs an AST node from any class implementing the `Declaration` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isDeclaration, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Declaration(std::move(t)));
}

} // namespace hilti
