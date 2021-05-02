// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/result.h>

namespace hilti {
namespace expression {

/**
 * AST node for an expression for which evaluation is deferred at runtime to
 * a later point when explicity requested by the runtime system. Optionally,
 * that later evaluation can catch any exceptions and return a corresponding
 * ``result<T>``.
 */
class Deferred : public NodeBase, public trait::isExpression {
public:
    Deferred(Expression e, Meta m = Meta()) : NodeBase(nodes(std::move(e), type::Auto(m)), std::move(m)) {}
    Deferred(Expression e, bool catch_exception, Meta m = Meta())
        : NodeBase(nodes(e, type::Auto(m)), m), _catch_exception(catch_exception) {}

    const auto& expression() const { return child<Expression>(0); }
    bool catchException() const { return _catch_exception; }

    bool operator==(const Deferred& other) const { return expression() == other.expression(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(1); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"catch_exception", _catch_exception}}; }

private:
    bool _catch_exception;
};

} // namespace expression
} // namespace hilti
