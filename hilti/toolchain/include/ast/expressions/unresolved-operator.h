// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/auto.h>

namespace hilti {
namespace expression {

/** AST node for an expression representing an unresolved operator usage. */
class UnresolvedOperator : public NodeBase, public trait::isExpression {
public:
    UnresolvedOperator(operator_::Kind op, std::vector<Expression> operands, Meta meta = Meta())
        : NodeBase(nodes(type::Auto(), std::move(operands)), std::move(meta)), _kind(op) {}

    UnresolvedOperator(operator_::Kind op, node::range<Expression> operands, Meta meta = Meta())
        : NodeBase(nodes(type::Auto(), std::move(operands)), std::move(meta)), _kind(op) {}

    auto kind() const { return _kind; }

    bool areOperandsResolved() const {
        for ( auto op : childs<Expression>(1, -1) ) {
            if ( ! type::isResolved(op.type()) )
                return false;
        }

        return true;
    }

    /** Implements interfave for use with `OverloadRegistry`. */
    auto operands() const { return childs<Expression>(1, -1); }

    bool operator==(const UnresolvedOperator& other) const {
        return kind() == other.kind() && operands() == other.operands();
    }

    /** Implements `Expression` interface. */

    // Dummy implementations as the node will be rejected in validation anyway.
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(0); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"kind", to_string(_kind)}}; }

private:
    operator_::Kind _kind;
};

} // namespace expression
} // namespace hilti
