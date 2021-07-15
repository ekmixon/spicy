// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for a regexp type. */
class RegExp : public TypeBase, trait::isAllocable, trait::isRuntimeNonTrivial {
public:
    RegExp(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const RegExp& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace type
} // namespace hilti
