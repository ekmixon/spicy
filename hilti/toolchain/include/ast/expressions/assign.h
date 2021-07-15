// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti {
namespace expression {

/** AST node for an assign expression. */
class Assign : public NodeBase, public trait::isExpression {
public:
    Assign(Expression target, Expression src, Meta m = Meta())
        : NodeBase({std::move(target), std::move(src)}, std::move(m)) {}

    const auto& source() const { return child<Expression>(1); }
    const auto& target() const { return child<Expression>(0); }

    void setSource(hilti::Expression c) { childs()[1] = std::move(c); }
    void setTarget(hilti::Expression c) { childs()[0] = std::move(c); }

    bool operator==(const Assign& other) const { return target() == other.target() && source() == other.source(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return target().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return isLhs(); }
    /** Implements `Expression` interface. */
    const auto& type() const { return target().type(); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
