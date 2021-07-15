// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/library.h>

namespace hilti {
namespace expression {

/** AST node for a "move" expression. */
class TypeInfo : public NodeBase, public trait::isExpression {
public:
    TypeInfo(Expression e, Meta m = Meta())
        : NodeBase(nodes(std::move(e), Type(type::Library("const hilti::rt::TypeInfo*"))), std::move(m)) {}

    const auto& expression() const { return child<Expression>(0); }

    bool operator==(const TypeInfo& other) const { return expression() == other.expression(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(1); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return true; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
