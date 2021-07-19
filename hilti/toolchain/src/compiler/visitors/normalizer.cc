// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>

#include "ast/declarations/imported-module.h"
#include "base/logger.h"

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Normalizer("normalizer");
} // namespace hilti::logging::debug
namespace {


struct Visitor : public visitor::PreOrder<void, Visitor> {
    bool modified = false;

    // Log debug message recording resolving a epxxression.
    void logChange(const Node& old, const Expression& nexpr) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const Statement& nstmt) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const Type& ntype) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> type %s (%s)", old.typename_(), old, ntype, old.location()));
    }

    void operator()(const declaration::Function& u, position_t p) {
        if ( u.linkage() == declaration::Linkage::Struct ) {
            // Link method implementations to their parent type.
            auto ns = u.id().namespace_();
            if ( ! ns )
                return;

            auto resolved = scope::lookupID<declaration::Type>(ns, p, "struct type");
            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            if ( ! resolved->first->isA<declaration::Type>() ) {
                p.node.addError(
                    util::fmt("namespace %s does not resolve to a type (but to %s)", ns, resolved->first->typename_()));
                return;
            }

            p.node.as<declaration::Function>().setParentRef(NodeRef(resolved->first));
        }
    }

    void operator()(const expression::Assign& assign, position_t p) {
        // Rewrite assignments to map elements to use the `index_assign` operator.
        auto& lhs = assign.childs().front();
        if ( auto index_non_const = lhs.tryAs<operator_::map::IndexNonConst>() ) {
            const auto& map = index_non_const->op0();
            const auto& map_type = map.type().as<type::Map>();
            const auto& key_type = map_type.keyType();
            const auto& value_type = map_type.valueType();

            auto key = index_non_const->op1();
            if ( key.type() != key_type ) {
                if ( auto nexpr = hilti::coerceExpression(key, key_type).nexpr )
                    key = std::move(*nexpr);
            }

            auto value = assign.source();
            if ( value.type() != value_type ) {
                if ( auto nexpr = hilti::coerceExpression(value, value_type).nexpr )
                    value = std::move(*nexpr);
            }

            Expression index_assign =
                hilti::expression::UnresolvedOperator(hilti::operator_::Kind::IndexAssign,
                                                      {std::move(map), std::move(key), std::move(value)},
                                                      assign.meta());

            logChange(p.node, index_assign);
            p.node = std::move(index_assign);
            modified = true;
            return;
        }

        // Rewrite assignments involving struct elements to use the non-const member operator.
        if ( auto member_const = lhs.tryAs<operator_::struct_::MemberConst>() ) {
            auto new_lhs =
                operator_::struct_::MemberNonConst::Operator().instantiate(member_const->operands().copy<Expression>(),
                                                                           member_const->meta());
            Expression n = expression::Assign(new_lhs, assign.source(), assign.meta());
            logChange(p.node, n);
            p.node = std::move(n);
            modified = true;
            return;
        }
    }

    void operator()(const statement::If& n, position_t p) {
        if ( n.init() && ! n.condition() ) {
            auto cond = expression::UnresolvedID(n.init()->id());
            logChange(p.node, cond);
            p.node.as<statement::If>().setCondition(std::move(cond));
            modified = true;
        }
    }

    void operator()(const type::Struct& m, position_t p) { type::Struct::setSelf(&p.node); }
};

} // anonymous namespace

struct VisitorCanonicalIDs : public visitor::PreOrder<ID, VisitorCanonicalIDs> {
    ID parent_id;
    bool modified = false;

    result_t operator()(const Module& m, position_t p) { return m.id(); }

    result_t operator()(const Declaration& d, position_t p) {
        auto id = ID(parent_id, d.id());

        if ( d.canonicalID() != id ) {
            p.node.as<Declaration>().setCanonicalID(id);
        }

        return id;
    }

    result_t operator()(const type::struct_::Field& f, position_t p) {
        // TODO: Should a field be a declaration, too?
        auto id = ID(parent_id, f.id());

        if ( f.canonicalID() != id ) {
            p.node.as<type::struct_::Field>().setCanonicalID(id);
        }

        return id;
    }
};

static void _computeCanonicalIDs(VisitorCanonicalIDs* v, Node* node, ID current) {
    if ( node->isAlias() )
        return;

    node->scope()->initCanonicalIDs(current);
    v->parent_id = current;
    if ( auto x = v->dispatch(node) )
        current = *x;

    for ( auto& c : node->childs() )
        _computeCanonicalIDs(v, &c, current);
}

bool hilti::detail::ast::normalize(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/ast/normalizer");

    auto v1 = Visitor();
    for ( auto i : v1.walk(root) )
        v1.dispatch(i);

    // (Re-)compute canonical IDs.
    auto v2 = VisitorCanonicalIDs();
    _computeCanonicalIDs(&v2, root, ID());

    return v1.modified || v2.modified;
}

// Putting here for lack of a better place.
void hilti::detail::ast::clearErrors(Node* root) {
    for ( const auto&& i : hilti::visitor::PreOrder<>().walk(root) )
        i.node.clearErrors();
}
