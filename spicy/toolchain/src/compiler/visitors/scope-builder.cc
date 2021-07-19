// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

struct Visitor : public hilti::visitor::PostOrder<void, Visitor> {
    explicit Visitor(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;

    void operator()(const type::Unit& t, position_t p) {
        if ( t.selfRef() )
            p.node.scope()->insert(t.selfRef());

        for ( auto&& x : t.parameterRefs() )
            p.parent().scope()->insert(std::move(x));
    }
};

} // anonymous namespace

void spicy::detail::ast::buildScopes(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    (*hilti::plugin::registry().hiltiPlugin().ast_build_scopes)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/ast/scope-builder");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);
}
