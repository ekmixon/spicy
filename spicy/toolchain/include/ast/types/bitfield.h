// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/unknown.h>

#include <spicy/ast/aliases.h>

namespace spicy {
namespace type {

namespace bitfield {

/** AST node for a bitfield element. */
class Bits : public hilti::NodeBase {
public:
    Bits() : NodeBase({ID("<no id>"), hilti::node::none}, Meta()) {}
    Bits(ID id, int lower, int upper, int field_width, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : hilti::NodeBase(nodes(std::move(id), hilti::type::auto_, std::move(attrs)), std::move(m)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    const auto& id() const { return child<ID>(0); }
    auto lower() const { return _lower; }
    auto upper() const { return _upper; }
    auto fieldWidth() const { return _field_width; }
    const auto& type() const { return child<Type>(1); }
    auto attributes() const { return childs()[2].tryReferenceAs<AttributeSet>(); }

    /** Implements the `Node` interface. */
    auto properties() const {
        return node::Properties{
            {"lower", _lower},
            {"upper", _upper},
            {"field_width", _field_width},
        };
    }

    void setAttributes(AttributeSet attrs) { childs()[2] = std::move(attrs); }
    void setType(Type t) { childs()[1] = std::move(t); }

    bool operator==(const Bits& other) const {
        return id() == other.id() && _lower == other._lower && _upper == other._upper &&
               _field_width == other._field_width && type() == other.type() && attributes() == other.attributes();
    }

private:
    int _lower = 0;
    int _upper = 0;
    int _field_width = 0;
};

inline hilti::Node to_node(Bits f) { return hilti::Node(std::move(f)); }

} // namespace bitfield

/** AST node for a struct type. */
class Bitfield : public hilti::TypeBase,
                 hilti::type::trait::isAllocable,
                 hilti::type::trait::isParameterized,
                 hilti::type::trait::isMutable {
public:
    Bitfield(int width, std::vector<bitfield::Bits> bits, Meta m = Meta())
        : TypeBase(nodes(hilti::type::auto_, std::move(bits)), std::move(m)), _width(width) {}
    Bitfield(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({}, std::move(m)), _wildcard(true) {}

    int width() const { return _width; }
    auto bits() const { return childs<bitfield::Bits>(1, -1); }
    hilti::optional_ref<const bitfield::Bits> bits(const ID& id) const;
    std::optional<int> bitsIndex(const ID& id) const;
    const Type& type() const { return child<Type>(0); }

    void addField(bitfield::Bits f) { addChild(std::move(f)); }
    void setType(Type t) { childs()[0] = std::move(t); }

    bool operator==(const Bitfield& other) const { return width() == other.width() && bits() == other.bits(); }

    /** For internal use by the builder API only. */
    auto _bitsNodes() { return nodesOfType<bitfield::Bits>(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return hilti::util::slice(childs(), 1); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    int _width = 0;
    bool _wildcard = false;
};

} // namespace type
} // namespace spicy
