// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/operators/reference.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/unknown.h>

#include "ast/expressions/grouping.h"
#include "ast/types/reference.h"

namespace hilti {
namespace type {

namespace struct_ {
/** AST node for a struct field. */
class Field : public NodeBase {
public:
    Field() : NodeBase({ID("<no id>"), type::unknown, node::none, node::none}, Meta()) {}
    Field(ID id, Type t, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(t), node::none, std::move(attrs), node::none), std::move(m)) {}
    Field(ID id, Type t, Type aux_type, std::optional<AttributeSet> attrs, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(t), std::move(aux_type), std::move(attrs), node::none),
                   std::move(m)) {}
    Field(ID id, ::hilti::function::CallingConvention cc, type::Function ft, std::optional<AttributeSet> attrs = {},
          Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(ft), node::none, std::move(attrs), node::none), std::move(m)),
          _cc(cc) {}
    Field(ID id, hilti::Function inline_func, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), node::none, node::none, std::move(attrs), std::move(inline_func)),
                   std::move(m)),
          _cc(inline_func.callingConvention()) {}

    const auto& id() const { return child<ID>(0); }

    const auto& canonicalID() const { return _canon_id; } // set by Normalizer
    void setCanonicalID(ID id) { _canon_id = std::move(id); }

    auto callingConvention() const { return _cc; }
    auto inlineFunction() const { return childs()[4].tryReferenceAs<hilti::Function>(); }
    auto attributes() const { return childs()[3].tryReferenceAs<AttributeSet>(); }
    bool isResolved(type::ResolvedState* rstate) const {
        if ( childs()[1].isA<type::Function>() )
            return true;

        if ( auto func = inlineFunction() )
            return type::isResolved(func->type(), rstate);
        else
            return type::isResolved(child<Type>(1), rstate);
    }

    const Type& type() const {
        if ( const auto& func = inlineFunction() )
            return func->type();
        else
            return child<Type>(1);
    }

    NodeRef typeRef() {
        if ( inlineFunction() )
            return childs()[4].as<hilti::Function>().typeRef();
        else
            return NodeRef(childs()[1]);
    }

    hilti::optional_ref<const Expression> default_() const {
        if ( auto a = AttributeSet::find(attributes(), "&default") ) {
            if ( auto x = a->valueAsExpression() )
                return x->get();
            else
                return {};
        }

        return {};
    }

    auto isInternal() const { return AttributeSet::find(attributes(), "&internal").has_value(); }
    auto isOptional() const { return AttributeSet::find(attributes(), "&optional").has_value(); }
    auto isStatic() const { return AttributeSet::find(attributes(), "&static").has_value(); }
    auto isNoEmit() const { return AttributeSet::find(attributes(), "&no-emit").has_value(); }

    /** Internal method for use by builder API only. */
    auto& _typeNode() {
        if ( auto func = inlineFunction() )
            return const_cast<::hilti::Function&>(*func)._typeNode();
        else
            return childs()[1];
    }

    void setAttributes(AttributeSet attrs) { childs()[3] = std::move(attrs); }

    bool operator==(const Field& other) const {
        return id() == other.id() && type() == other.type() && attributes() == other.attributes() && _cc == other._cc;
    }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"cc", to_string(_cc)}, {"canon_id", _canon_id}}; }

private:
    ::hilti::function::CallingConvention _cc = ::hilti::function::CallingConvention::Standard;
    ID _canon_id;
}; // namespace struct_

inline Node to_node(Field f) { return Node(std::move(f)); }

} // namespace struct_

/** AST node for a struct type. */
class Struct : public TypeBase, trait::isAllocable, trait::isParameterized, trait::takesArguments, trait::isMutable {
public:
    Struct(std::vector<struct_::Field> fields, Meta m = Meta()) : TypeBase(nodes(node::none, std::move(fields)), m) {}

    Struct(std::vector<type::function::Parameter> params, std::vector<struct_::Field> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields),
                         util::transform(params,
                                         [](auto p) {
                                             p.setIsTypeParameter();
                                             return Declaration(p);
                                         })),
                   std::move(m)) {}

    Struct(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(node::none), m), _wildcard(true) {}

    NodeRef selfRef() const {
        if ( childs()[0].isA<Declaration>() )
            return NodeRef(childs()[0]);
        else
            return {};
    }

    auto hasFinalizer() const { return field("~finally").has_value(); }
    auto parameters() const { return childsOfType<type::function::Parameter>(); }
    auto parameterRefs() const { return refsOfType<type::function::Parameter>(); }

    auto fields() const { return childsOfType<struct_::Field>(); }

    hilti::optional_ref<const struct_::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    hilti::node::set<const struct_::Field> fields(const ID& id) const {
        hilti::node::set<const struct_::Field> x;
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                x.push_back(f);
        }

        return x;
    }

    bool operator==(const Struct& other) const { return fields() == other.fields(); }

    /** For internal use by the builder API only. */
    auto _fieldNodes() { return nodesOfType<struct_::Field>(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        for ( const auto& c : childs() ) {
            if ( auto f = c.tryAs<struct_::Field>() ) {
                if ( ! f->isResolved(rstate) )
                    return false;
            }
            else if ( auto p = c.tryAs<type::function::Parameter>() )
                if ( ! p->isResolved(rstate) )
                    return false;
        }

        return true;
    }

    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( const auto& f : fields() )
            params.emplace_back(f.type());
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
    static Struct addField(const Struct& s, struct_::Field f) {
        auto x = Type(s)._clone().as<Struct>();
        x.addChild(std::move(f));
        return x;
    }

    /**
     * Given an existing node wrapping a struct type, updates the contained
     * struct type to have its `self` declaration initialized. Note that the
     * struct type's constructor cannot do this because we need the `Node`
     * shell for this.
     */
    static void setSelf(Node* n) {
        assert(n->isA<type::Struct>());
        n->childs()[0] = Declaration(Struct::_self(*n, n->meta()));
    }

private:
    static Declaration _self(Node& n, const Meta& m) {
        Expression self = expression::Keyword(expression::keyword::Kind::Self, type::ValueReference(NodeRef(n)), m);
        return declaration::Expression("self", expression::Grouping(expression::Grouping(std::move(self))),
                                       declaration::Linkage::Private, m);
    }

    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
