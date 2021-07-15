// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

class Switch;

namespace switch_ {

using Default = struct {};

/**
 * AST node for a switch case type.
 *
 * Note that internally, we store the expressions in a preprocessed matter:
 * `E` turns into `<id> == E`, where ID is selected to match the code
 * generator's output. Doing this allows coercion for the comparision to
 * proceed normally. The preprocessing happens at the time the `Case` gets
 * added to a `Switch` statement, and the new versions are stored separately
 * from the original expressions.
 */
class Case : public NodeBase {
public:
    Case(hilti::Expression expr, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(expr)), std::move(m)), _end_exprs(2) {}
    Case(std::vector<hilti::Expression> exprs, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(exprs)), std::move(m)), _end_exprs(childs().size()) {}
    Case(Default /*unused*/, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body)), std::move(m)), _end_exprs(1) {}
    Case() = default;

    auto expressions() const { return childs<hilti::Expression>(1, _end_exprs); }
    auto preprocessedExpressions() const { return childs<hilti::Expression>(_end_exprs, -1); }
    const auto& body() const { return child<Statement>(0); }

    bool isDefault() const { return expressions().empty(); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return childs()[0]; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Case& other) const { return expressions() == other.expressions() && body() == other.body(); }

private:
    friend class hilti::statement::Switch;

    void _addPreprocessedExpression(const std::string& id, const hilti::Expression& e) {
        hilti::Expression n =
            expression::UnresolvedOperator(operator_::Kind::Equal, {expression::UnresolvedID(ID(id)), e}, e.meta());

        childs().emplace_back(std::move(n));
    }

    int _end_exprs{};
};

inline Node to_node(Case c) { return Node(std::move(c)); }

} // namespace switch_

/** AST node for a "switch" statement. */
class Switch : public NodeBase, public hilti::trait::isStatement {
public:
    Switch(hilti::Expression cond, const std::vector<switch_::Case>& cases, Meta m = Meta())
        : Switch(hilti::declaration::LocalVariable(hilti::ID("__x"), std::move(cond), true, m), std::move(cases), m) {}

    Switch(const hilti::Declaration& cond, const std::vector<switch_::Case>& cases, Meta m = Meta())
        : NodeBase(nodes(cond, cases), std::move(m)) {
        if ( ! cond.isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'switch' must be a local declaration");
        _preprocessCases(cond.id());
    }

    const auto& condition() const { return childs()[0].as<hilti::declaration::LocalVariable>(); }
    auto conditionRef() const { return NodeRef(childs()[0]); }
    auto cases() const { return childs<switch_::Case>(1, -1); }

    hilti::optional_ref<const switch_::Case> default_() const {
        for ( const auto& c : childs<switch_::Case>(1, -1) ) {
            if ( c.isDefault() )
                return c;
        }
        return {};
    }

    bool operator==(const Switch& other) const {
        return condition() == other.condition() && default_() == other.default_() && cases() == other.cases();
    }

    /** Internal method for use by builder API only. */
    auto& _lastCaseNode() { return childs().back(); }

    /** Internal method for use by builder API only. */
    void _addCase(switch_::Case case_) {
        for ( const auto& e : case_.expressions() )
            case_._addPreprocessedExpression(_id, e);

        addChild(std::move(case_));
    }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    void _preprocessCases(const std::string& id) {
        _id = id;

        for ( auto i = 1; i < childs().size(); i++ ) {
            auto& case_ = childs()[i].as<switch_::Case>();
            for ( auto j = 0; j < case_.expressions().size(); j++ )
                case_._addPreprocessedExpression(id, case_.expressions()[j]);
        }
    }

    std::string _id;
};

} // namespace statement
} // namespace hilti
