// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/util.h>

namespace hilti {
namespace expression {

namespace keyword {
// Type of a reserved keyword
enum class Kind {
    Self,         /**< `self` */
    DollarDollar, /**< `$$` */
    Captures      /**< `$@` */
};

namespace detail {
constexpr util::enum_::Value<Kind> kinds[] = {{Kind::Self, "self"}, {Kind::DollarDollar, "$$"}, {Kind::Captures, "$@"}};
} // namespace detail

namespace kind {
constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Kind>(s, detail::kinds); }
} // namespace kind

constexpr auto to_string(Kind m) { return util::enum_::to_string(m, detail::kinds); }

} // namespace keyword

/** AST node for an expression representing a reservered keyword. */
class Keyword : public NodeBase, public hilti::trait::isExpression {
public:
    Keyword(keyword::Kind kind, Meta m = Meta()) : NodeBase(nodes(type::unknown), std::move(m)), _kind(kind) {}
    Keyword(keyword::Kind kind, Type t, Meta m = Meta()) : NodeBase(nodes(std::move(t)), std::move(m)), _kind(kind) {}
    Keyword(keyword::Kind kind, NodeRef t, Meta m = Meta())
        : NodeBase(nodes(node::none), std::move(m)), _kind(kind), _type(std::move(t)) {}

    keyword::Kind kind() const { return _kind; }

    bool operator==(const Keyword& other) const { return _kind == other._kind && type() == other.type(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return true; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    const Type& type() const {
        if ( auto x = childs()[0].tryAs<Type>() )
            return *x;
        else
            return _type ? _type->as<Type>() : type::unknown;
    }

    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"kind", to_string(_kind)}, {"node", _type.renderedRid()}}; }

private:
    keyword::Kind _kind;
    NodeRef _type;
};

} // namespace expression
} // namespace hilti
