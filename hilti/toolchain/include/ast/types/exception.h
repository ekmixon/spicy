// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for an `exception` type. */
class Exception : public TypeBase, trait::isAllocable, trait::isParameterized {
public:
    Exception(Meta m = Meta()) : TypeBase({node::none}, std::move(m)) {}
    Exception(Type base, Meta m = Meta()) : TypeBase({std::move(base)}, std::move(m)) {}
    Exception(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}

    hilti::optional_ref<const Type> baseType() const { return childs()[0].tryReferenceAs<Type>(); }

    bool operator==(const Exception& other) const { return baseType() == other.baseType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        return baseType().has_value() ? type::isResolved(baseType(), rstate) : true;
    }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
