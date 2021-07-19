// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>

#include <spicy/ast/types/unit-items/unit-hook.h>

namespace spicy {
namespace declaration {

/** AST node for a declaration of an external (i.e., module-level) unit hook. */
class UnitHook : public hilti::DeclarationBase {
public:
    UnitHook(ID id, Type unit, const type::unit::Item& hook, Meta m = Meta())
        : DeclarationBase(hilti::nodes(std::move(id), std::move(unit), hook), std::move(m)) {
        if ( ! hook.isA<type::unit::item::UnitHook>() )
            hilti::logger().internalError("non-unit hook passed into declaration::UnitHook");
    }

    const auto& unitHook() const { return child<type::unit::item::UnitHook>(2); }

    hilti::optional_ref<const spicy::type::Unit> unitType() const {
        if ( _unit_type )
            return _unit_type->as<hilti::declaration::Type>().type().as<spicy::type::Unit>();
        else
            return {};
    }

    void setUnitTypeRef(NodeRef p) { _unit_type = std::move(p); }

    bool operator==(const UnitHook& other) const {
        return unitType() == other.unitType() && unitHook() == other.unitHook();
    }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const auto& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Private; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "unit hook"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    NodeRef _unit_type;
};

} // namespace declaration
} // namespace spicy
