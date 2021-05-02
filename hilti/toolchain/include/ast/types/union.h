// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

namespace union_ {
/** AST node for a struct field. */
class Field : public NodeBase {
public:
    Field() : NodeBase({ID("<no id>"), type::unknown, node::none}, Meta()) {}
    Field(ID id, Type t, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(t), std::move(attrs)), std::move(m)) {}

    const auto& id() const { return child<ID>(0); }
    const auto& type() const { return child<Type>(1); }
    auto attributes() const { return childs()[2].tryReferenceAs<AttributeSet>(); }
    bool isResolved(type::ResolvedState* rstate) const { return type::isResolved(child<Type>(1), rstate); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Field& other) const {
        return id() == other.id() && type() == other.type() && attributes() == other.attributes();
    }
};

inline Node to_node(Field f) { return Node(std::move(f)); }

} // namespace union_

/** AST node for a struct type. */
class Union : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isMutable {
public:
    Union(std::vector<union_::Field> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields)), std::move(m)) {}
    Union(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _wildcard(true) {}

    auto fields() const { return childsOfType<union_::Field>(); }

    hilti::optional_ref<const union_::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    unsigned int index(const ID& id) const {
        for ( const auto&& [i, f] : util::enumerate(fields()) ) {
            if ( f.id() == id )
                return i + 1;
        }

        return 0;
    }

    bool operator==(const Union& other) const { return fields() == other.fields(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        for ( auto c = ++childs().begin(); c != childs().end(); c++ ) {
            if ( ! c->as<union_::Field>().isResolved(rstate) )
                return false;
        }

        return true;
    }

    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( auto c = ++childs().begin(); c != childs().end(); c++ )
            params.emplace_back(c->as<union_::Field>().type());
        return params;
    }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Copies an existing type and adds a new field to the copy.
     *
     * @param s original type
     * @param f field to add
     * @return new typed with field added
     */
    static Union addField(const Union& s, union_::Field f) {
        auto x = Type(s)._clone().as<Union>();
        x.addChild(std::move(f));
        return x;
    }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
