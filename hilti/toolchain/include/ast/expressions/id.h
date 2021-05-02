// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/types/auto.h>
#include <hilti/base/logger.h>

namespace hilti {
namespace expression {

// TODO: Would be nice for consisteny with type::ResolvedID to move this over
// to using a NodeRef, but I'm getting dangling references when I'm doing that.

/** AST node for a expression representing a resolved ID. */
class ResolvedID : public NodeBase, hilti::trait::isExpression {
public:
    ResolvedID(ID id, Node d, Meta m = Meta()) : NodeBase(nodes(std::move(id), node::makeAlias(std::move(d))), m) {}

    const auto& id() const { return child<ID>(0); }
    const auto& declaration() const { return child<Declaration>(1); }
    const Node& node() const { return childs()[1]; }

    bool operator==(const ResolvedID& other) const {
        return id() == other.id() && declaration() == other.declaration();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return ! declaration().isConstant(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    const Type& type() const;
    /** Implements `Expression` interface. */
    bool isConstant() const;
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{}}; }
};

/** AST node for a expression representing an unresolved ID. */
class UnresolvedID : public NodeBase, hilti::trait::isExpression {
public:
    UnresolvedID(ID id, Meta m = Meta()) : NodeBase(nodes(std::move(id), type::Auto()), std::move(m)) {}

    const auto& id() const { return child<ID>(0); }

    bool operator==(const UnresolvedID& other) const { return id() == other.id(); }

    // Expression interface.
    bool isLhs() const { return true; }
    bool isTemporary() const { return false; }
    const Type& type() const { return child<Type>(1); }
    auto isConstant() const { return false; }
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
