// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <functional>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/grouping.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/operators/reference.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

/** AST node for a struct type. */
class Struct : public TypeBase, trait::isAllocable, trait::isParameterized, trait::takesArguments, trait::isMutable {
public:
    Struct(std::vector<Declaration> fields, Meta m = Meta()) : TypeBase(nodes(node::none, std::move(fields)), m) {}

    Struct(std::vector<type::function::Parameter> params, std::vector<Declaration> fields, Meta m = Meta())
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
    auto parameterRefs() const { return childRefsOfType<type::function::Parameter>(); }

    auto fields() const { return childsOfType<declaration::Field>(); }

    hilti::optional_ref<const declaration::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    hilti::node::Set<const declaration::Field> fields(const ID& id) const {
        hilti::node::Set<const declaration::Field> x;
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                x.insert(f);
        }

        return x;
    }

    void addField(Declaration f) {
        assert(f.isA<declaration::Field>());
        addChild(std::move(f));
    }

    bool operator==(const Struct& other) const { return fields() == other.fields(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        for ( const auto& c : childs() ) {
            if ( auto f = c.tryAs<declaration::Field>() ) {
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
     * Given an existing node wrapping a struct type, updates the contained
     * struct type to have its `self` declaration initialized. The struct
     * type's constructor cannot do this because we need the `Node` shell for
     * this.
     */
    static void setSelf(Node* n) {
        assert(n->isA<type::Struct>());
        Expression self =
            expression::Keyword(expression::keyword::Kind::Self, type::ValueReference(NodeRef(*n)), n->meta());
        Declaration d = declaration::Expression("self", std::move(self), declaration::Linkage::Private, n->meta());
        n->childs()[0] = std::move(d);
    }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
