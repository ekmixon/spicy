// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/statement.h>

#include "ast/declarations/type.h"

namespace hilti {
namespace declaration {

/** AST node for a declaration of an function. */
class Function : public DeclarationBase {
public:
    Function(::hilti::Function function, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(function)), std::move(m)), _linkage(linkage) {}

    const ::hilti::Function& function() const { return child<::hilti::Function>(0); }

    hilti::optional_ref<const hilti::Type> parentType() const {
        if ( _parent_type )
            return _parent_type->as<declaration::Type>().type();
        else
            return {};
    }

    void setLinkage(Linkage x) { _linkage = x; }
    void setParentRef(NodeRef p) { _parent_type = std::move(p); }

    bool operator==(const Function& other) const { return id() == other.id() && function() == other.function(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return function().id(); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "function"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const {
        return node::Properties{{"linkage", to_string(_linkage)}, {"parent_type", _parent_type.renderedRid()}};
    }

private:
    Linkage _linkage;
    NodeRef _parent_type;
};

} // namespace declaration
} // namespace hilti
