// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>
#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit sink.
 */
class Sink : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Sink(ID id, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(attrs), type::Sink(m)), m) {}

    const auto& id() const { return child<ID>(0); }
    auto attributes() const { return childs()[1].tryReferenceAs<AttributeSet>(); }

    bool operator==(const Sink& other) const { return id() == other.id() && attributes() == other.attributes(); }

    // Unit field interface
    const Type& itemType() const { return child<Type>(2); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{}; }
};

} // namespace spicy::type::unit::item
