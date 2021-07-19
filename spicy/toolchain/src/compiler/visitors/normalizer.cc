// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/type.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Normalizer("normalizer");
} // namespace hilti::logging::debug

namespace {

struct Visitor : public hilti::visitor::PreOrder<void, Visitor> {
    explicit Visitor(Node* root) : root(root) {}
    Node* root;
    bool modified = false;

    // Log debug message recording resolving a epxxression.
    void logChange(const Node& old, const Expression& nexpr) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const Statement& nstmt) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const Type& ntype) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> type %s (%s)", old.typename_(), old, ntype, old.location()));
    }

    void logChange(const Node& old, const std::string_view msg) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, msg, old.location()));
    }

    void operator()(const hilti::declaration::Type& t, position_t p) {
        if ( auto u = t.type().tryAs<type::Unit>() ) {
            if ( t.linkage() == declaration::Linkage::Public && ! u->isPublic() ) {
                logChange(p.node, "set public");
                const_cast<type::Unit&>(t.type().as<type::Unit>()).setPublic(true);
                modified = true;
            }

            // Create unit property items from global module items where the unit
            // does not provide an overriding one.
            std::vector<type::unit::Item> ni;
            for ( const auto& prop : root->as<Module>().moduleProperties({}) ) {
                if ( u->propertyItem(prop.id()) )
                    continue;

                auto i = type::unit::item::Property(prop.id(), *prop.expression(), {}, true, prop.meta());
                logChange(p.node, hilti::util::fmt("add module-level property %s", prop.id()));
                const_cast<type::Unit&>(t.type().as<type::Unit>()).addItems({std::move(i)});
                modified = true;
            }
        }
    }

    void operator()(const declaration::UnitHook& u, position_t p) {
        if ( u.unitType() )
            return;

        // Link hook to its parent type.
        auto ns = u.id().namespace_();
        if ( ! ns )
            return;

        auto resolved = hilti::scope::lookupID<hilti::declaration::Type>(ns, p, "unit type");
        if ( ! resolved ) {
            p.node.addError(resolved.error());
            return;
        }

        if ( ! resolved->first->isA<hilti::declaration::Type>() ) {
            p.node.addError(hilti::util::fmt("namespace %s does not resolve to a unit type (but to %s)", ns,
                                             resolved->first->typename_()));
            return;
        }

        logChange(p.node, resolved->first->as<Type>());
        p.node.as<spicy::declaration::UnitHook>().setUnitTypeRef(NodeRef(resolved->first));
        modified = true;
    }

    void operator()(const hilti::expression::Assign& assign, position_t p) {
        // Rewrite assignments involving unit fields to use the non-const member operator.
        if ( auto member_const = assign.childs().front().tryAs<operator_::unit::MemberConst>() ) {
            auto new_lhs =
                operator_::unit::MemberNonConst::Operator().instantiate(member_const->operands().copy<Expression>(),
                                                                        member_const->meta());
            Expression n = hilti::expression::Assign(new_lhs, assign.source(), assign.meta());
            logChange(p.node, n);
            p.node = std::move(n);
            modified = true;
            return;
        }
    }

    void operator()(const type::Unit& u, position_t p) {
        if ( ! u.selfRef() )
            type::Unit::setSelf(&p.node);

        const auto& t = p.node.as<Type>();

        if ( ! t.hasFlag(type::Flag::NoInheritScope) ) {
            logChange(p.node, "set no-inherit");
            p.node.as<Type>().addFlag(type::Flag::NoInheritScope);
            modified = true;
        }

        if ( t.typeID() && ! u.id() ) {
            logChange(p.node, hilti::util::fmt("unit ID %s", *t.typeID()));
            p.node.as<type::Unit>().setID(*t.typeID());
            modified = true;
        }
    }
};

} // anonymous namespace

bool spicy::detail::ast::normalize(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_normalize)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/normalizer");

    auto v = Visitor(root);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified || hilti_modified;
}
