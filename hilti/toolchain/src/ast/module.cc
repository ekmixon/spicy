// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/module.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

void Module::clear() {
    auto v = visitor::PostOrder<>();

    // We fully walk the AST here in order to break any reference cycles it may
    // contain. Start at child 1 to leave ID in place.
    for ( size_t i = 1; i < childs().size(); i++ ) {
        for ( auto j : v.walk(&childs()[i]) )
            j.node = node::none;
    }

    childs()[1] = statement::Block({}, meta());
}

NodeRef Module::preserve(Node n) {
    detail::ast::clearErrors(&n);
    _preserved.push_back(std::move(n));
    return NodeRef(_preserved.back());
}

hilti::optional_ref<const declaration::Property> Module::moduleProperty(const ID& id) const {
    for ( const auto& d : declarations() ) {
        if ( ! d.isA<declaration::Property>() )
            return {};

        auto& x = d.as<declaration::Property>();
        if ( x.id() == id )
            return {x};
    }

    return {};
}

node::set<declaration::Property> Module::moduleProperties(const std::optional<ID>& id) const {
    node::set<declaration::Property> props;

    for ( const auto& d : declarations() ) {
        if ( auto p = d.tryAs<declaration::Property>(); p && (! id || p->id() == id) )
            props.push_back(*p);
    }

    return props;
}
