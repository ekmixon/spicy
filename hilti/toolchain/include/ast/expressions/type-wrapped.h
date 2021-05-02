// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti {
namespace expression {

/**
 * TODO: Update comment to new API.
 *
 * AST node for an expression wrapped into another which does not have a
 * known type yet, for example because IDs are stil unresolved. With a
 * "normal" expression, calling `type()` would yield an unusable type. This
 * expression instead returns a place-holder type that's derived on one of
 * two ways:
 *
 *     1. If the fully resolved type of the expression is actually known
 *        a-priori, it can be jsut passed into the constructor and will then
 *        always be returned, independent of the inner expression's type
 *        itself.
 *
 *     2. If no explicit type is given, `type()` returns a proxy type that
 *        evaluates the expression's type on demand once requested (but not,
 *        crucially, immediately). So once the expression is fully resolved,
 *        this will yield its correct type. In the meantime, the proxy can be
 *        passed around like any other type.
 *
 * In case 1, one can in addition require that the expression's eventual
 * fully-resolved type matches the type that was specified. If it doesn't the
 * validator will then reject the code.
 *
 */
class TypeWrapped : public NodeBase, public trait::isExpression {
public:
    TypeWrapped(Expression e, Type t, Meta m = Meta()) : NodeBase(nodes(std::move(e), std::move(t)), std::move(m)) {}

    const auto& expression() const { return child<Expression>(0); }

    bool operator==(const TypeWrapped& other) const {
        return expression() == other.expression() && type() == other.type();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return expression().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return expression().isTemporary(); }
    /** Implements `Expression` interface. */
    const Type& type() const { return childs()[1].as<Type>(); }

    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
