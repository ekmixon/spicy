// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti {
namespace statement {

/** AST node for a "if" statement. */
class If : public NodeBase, public hilti::trait::isStatement {
public:
    If(hilti::Declaration init, std::optional<hilti::Expression> cond, Statement true_, std::optional<Statement> false_,
       Meta m = Meta())
        : NodeBase(nodes(init, std::move(cond), std::move(true_), std::move(false_)), std::move(m)) {
        if ( ! init.isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'if' must be a local declaration");
    }

    If(hilti::Expression cond, Statement true_, std::optional<Statement> false_, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(cond), std::move(true_), std::move(false_)), std::move(m)) {}

    auto init() const { return childs()[0].tryReferenceAs<hilti::declaration::LocalVariable>(); }
    auto initRef() const {
        return childs()[0].isA<hilti::declaration::LocalVariable>() ? NodeRef(childs()[0]) : NodeRef();
    }
    auto condition() const { return childs()[1].tryReferenceAs<hilti::Expression>(); }
    const auto& true_() const { return child<hilti::Statement>(2); }
    auto false_() const { return childs()[3].tryReferenceAs<Statement>(); }

    void setCondition(hilti::Expression e) { childs()[1] = std::move(e); }

    bool operator==(const If& other) const {
        return init() == other.init() && condition() == other.condition() && true_() == other.true_() &&
               false_() == other.false_();
    }

    /** Internal method for use by builder API only. */
    auto& _trueNode() { return childs()[2]; }

    /** Internal method for use by builder API only. */
    auto& _falseNode() { return childs()[3]; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace statement
} // namespace hilti
