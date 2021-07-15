// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace ctor {

/** AST node for a tuple constructor. */
class Tuple : public NodeBase, public hilti::trait::isCtor {
public:
    Tuple(std::vector<Expression> v, Meta m = Meta()) : NodeBase(nodes(_inferType(v), std::move(v)), std::move(m)) {}
    Tuple(node::range<Expression> v, Meta m = Meta()) : Tuple(v.copy<Expression>(), std::move(m)) {}

    auto value() const { return childs<Expression>(1, -1); }

    void setElementTypes(std::vector<Type> t) { childs()[0] = type::Tuple(std::move(t), meta()); }

    bool operator==(const Tuple& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }

    /** Implements `Ctor` interface. */
    auto isLhs() const {
        if ( value().empty() )
            return false;

        for ( const auto& e : value() ) {
            if ( ! e.isLhs() )
                return false;
        }

        return true;
    }

    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    Type _inferType(const std::vector<Expression>& exprs) {
        for ( const auto& e : exprs ) {
            if ( ! expression::isResolved(e) )
                return type::Auto();
        }

        std::vector<Type> types;
        for ( const auto& e : exprs )
            types.push_back(e.type());

        return type::Tuple(std::move(types));
    }
};

} // namespace ctor
} // namespace hilti
