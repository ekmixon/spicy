// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>

namespace hilti {
namespace expression {

/** AST node for a logical "or" expression. */
class LogicalOr : public NodeBase, public trait::isExpression {
public:
    LogicalOr(Expression op0, Expression op1, Meta m = Meta())
        : NodeBase(nodes(std::move(op0), std::move(op1), type::Bool(m)), m) {}

    const auto& op0() const { return child<Expression>(0); }
    const auto& op1() const { return child<Expression>(1); }

    void setOp0(const Expression& op) { childs()[0] = std::move(op); }
    void setOp1(const Expression& op) { childs()[1] = std::move(op); }

    bool operator==(const LogicalOr& other) const { return op0() == other.op0() && op1() == other.op1(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(2); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return op0().isConstant() && op1().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
