// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/types/id.h>
#include <hilti/ast/types/reference.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
inline const hilti::logging::DebugStream Operator("operator");
} // namespace spicy::logging::debug

namespace {
// Turns an unresolved field into a resolved field.
template<typename T>
auto resolveField(const type::unit::item::UnresolvedField& u, const T& t) {
    auto field = type::unit::item::Field(u.fieldID(), std::move(t), u.engine(), u.arguments().copy<Expression>(),
                                         u.repeatCount(), u.sinks().copy<Expression>(), u.attributes(), u.condition(),
                                         u.hooks().copy<Hook>(), u.meta());

    assert(u.index());
    field.setIndex(*u.index());
    return field;
}

// Helpers for determining a unit field's parse/item tyoes.
struct FieldTypeVisitor : public hilti::visitor::PreOrder<Type, FieldTypeVisitor> {
    explicit FieldTypeVisitor(bool want_parse_type) : want_parse_type(want_parse_type) {}

    bool want_parse_type;

    result_t operator()(const type::Bitfield& t) { return want_parse_type ? t : t.type(); }
    result_t operator()(const hilti::type::RegExp& /* t */) { return hilti::type::Bytes(); }
};

static Type _adaptType(const Type& t, bool want_parse_type) {
    if ( auto e = FieldTypeVisitor(want_parse_type).dispatch(t) )
        return std::move(*e);
    else
        return t;
}

static Type _itemType(const Type& type, bool want_parse_type, bool is_container, Meta meta) {
    auto nt = _adaptType(type, want_parse_type);

    if ( is_container )
        return type::Vector(std::move(nt), meta);
    else
        return nt;
}

struct Visitor : public hilti::visitor::PostOrder<void, Visitor> {
    explicit Visitor(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
    bool modified = false;

    // Log debug message recording resolving a epxxression.
    void logChange(const Node& old, const Expression& nexpr) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const Statement& nstmt) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const Type& ntype, const char* msg = "type") {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, msg, ntype, old.location()));
    }

    // Log debug message recording resolving a unit item.
    void logChange(const Node& old, const type::unit::Item& i) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, i, old.location()));
    }

    void operator()(const type::bitfield::Bits& b, position_t p) {
        if ( type::isResolved(b.type()) )
            return;

        Type t;

        if ( auto a = AttributeSet::find(b.attributes(), "&convert") ) {
            t = a->valueAsExpression()->get().type();
            if ( ! type::isResolved(t) )
                return;
        }
        else
            t = hilti::type::UnsignedInteger(b.fieldWidth());

        logChange(p.node, t);
        p.node.as<type::bitfield::Bits>().setType(std::move(t));
        modified = true;
    }

    void operator()(const type::Bitfield& b, position_t p) {
        std::vector<hilti::type::tuple::Element> elems;

        for ( const auto& b : b.bits() ) {
            if ( ! type::isResolved(b.type()) )
                return;

            elems.emplace_back(b.id(), b.type());
        }

        auto t = type::Tuple(std::move(elems), b.meta());
        logChange(p.node, t);
        p.node.as<type::Bitfield>().setType(std::move(t));
        modified = true;
    }

    void operator()(const type::unit::item::Field& f, position_t p) {
        if ( ! type::isResolved(f.originalType()) )
            return;

        if ( ! type::isResolved(f.parseType()) ) {
            auto t = _itemType(f.originalType(), true, f.isContainer(), f.meta());
            logChange(p.node, t, "parse type");
            p.node.as<type::unit::item::Field>().setParseType(std::move(t));
            modified = true;
        }

        if ( ! type::isResolved(f.itemType()) ) {
            std::optional<Type> t;

            if ( auto x = f.convertExpression() ) {
                if ( hilti::expression::isResolved(*x) )
                    t = x->type();

                // If there's list comprehension, morph the type into a vector.
                // Assignment will transparently work.
                if ( auto x = t->tryAs<type::List>() )
                    t = hilti::type::Vector(x->elementType(), x->meta());
            }
            else if ( const auto& i = f.item(); i && i->isA<type::unit::item::Field>() )
                t = _itemType(i->itemType(), false, f.isContainer(), f.meta());
            else
                t = _itemType(f.originalType(), false, f.isContainer(), f.meta());

            if ( t ) {
                logChange(p.node, *t, "item type");
                p.node.as<type::unit::item::Field>().setItemType(std::move(*t));
                modified = true;
            }
        }
    }

    void replaceField(position_t* p, type::unit::Item i) {
        logChange(p->node, i);
        p->node = std::move(i);
        modified = true;
    }

    void operator()(const type::unit::item::UnresolvedField& u, position_t p) {
        if ( const auto& id = u.unresolvedID() ) { // check for unresolved IDs first to overrides the other cases below
            auto resolved = hilti::scope::lookupID<hilti::Declaration>(*id, p, "field");
            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            if ( auto t = resolved->first->tryAs<hilti::declaration::Type>() ) {
                Type tt = hilti::builder::typeByID(*id);

                // If a unit comes with a &convert attribute, we wrap it into a
                // subitem so that we have our recursive machinery available
                // (which we don't have for pure types).
                if ( auto unit_type = t->type().tryAs<type::Unit>();
                     unit_type && AttributeSet::has(unit_type->attributes(), "&convert") ) {
                    auto inner_field =
                        type::unit::item::Field({}, std::move(tt), spicy::Engine::All, u.arguments().copy<Expression>(),
                                                {}, {}, {}, {}, {}, u.meta());
                    inner_field.setIndex(*u.index());

                    auto outer_field =
                        type::unit::item::Field(u.fieldID(), std::move(inner_field), u.engine(), {}, u.repeatCount(),
                                                u.sinks().copy<Expression>(), u.attributes(), u.condition(),
                                                u.hooks().copy<Hook>(), u.meta());

                    outer_field.setIndex(*u.index());

                    replaceField(&p, std::move(outer_field));
                }

                else
                    // Default treatment for types is to create a corresponding field.
                    replaceField(&p, resolveField(u, std::move(tt)));
            }

            else if ( auto c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto ctor = c->value().tryAs<hilti::expression::Ctor>() )
                    replaceField(&p, resolveField(u, ctor->ctor()));
                else
                    p.node.addError("field value must be a constant");
            }
            else
                p.node.addError(hilti::util::fmt("field value must be a constant or type (but is a %s)",
                                                 resolved->first->as<hilti::Declaration>().displayName()));
        }

        else if ( auto c = u.ctor() )
            replaceField(&p, resolveField(u, *c));

        else if ( auto t = u.type() ) {
            if ( ! type::isResolved(t) )
                return;

            replaceField(&p, resolveField(u, *t));
        }

        else if ( auto i = u.item() )
            replaceField(&p, resolveField(u, *i));

        else
            hilti::logger().internalError("no known type for unresolved field", p.node.location());
    }

#if 0
    void operator()(const hilti::expression::Keyword& n, position_t p) {
        if ( n.kind() == hilti::expression::keyword::Kind::DollarDollar && ! n.isSet() ) {
            std::optional<Type> dd;

            if ( auto f = p.findParent<hilti::Function>() ) {
                for ( const auto& p : f->get().type().parameters() ) {
                    if ( p.id() == ID("__dd") ) {
                        // Inside a free function that defines a "__dd" parameter; use it.
                        dd = type::Computed(hilti::builder::id("__dd"));
                        break;
                    }
                }
            }

            if ( ! dd ) {
                auto f = p.findParent<type::unit::item::Field>();

                if ( ! f )
                    return;

                if ( auto t = p.findParent<spicy::Hook>() ) {
                    // Inside a field's hook.
                    if ( t->get().isForEach() )
                        dd = type::unit::item::Field::vectorElementTypeThroughSelf(f->get().id());
                    else
                        dd = f->get().itemType();
                }

                else if ( auto a = p.findParent<Attribute>() ) {
                    // Inside an attribute expression.
                    if ( a->get().tag() == "&until" || a->get().tag() == "&until-including" ||
                         a->get().tag() == "&while" )
                        dd = type::unit::item::Field::vectorElementTypeThroughSelf(f->get().id());
                    else {
                        dd = f->get().parseType();

                        if ( auto bf = dd->tryAs<type::Bitfield>() )
                            dd = type::UnsignedInteger(bf->width(), bf->meta());
                    }
                }
            }

            if ( dd )
                replaceNode(&p,
                            hilti::expression::Keyword(hilti::expression::keyword::Kind::DollarDollar, *dd,
                                                       p.node.meta()),
                            __LINE__);
            else {
                p.node.addError("$$ not supported here");
                return;
            }
        }
    }

    void operator()(const type::Unit& n, position_t p) {
        if ( auto t = p.parent().tryAs<hilti::declaration::Type>();
             ! t && ! p.parent(2).tryAs<hilti::declaration::Type>() )
            replaceNode(&p, hilti::type::UnresolvedID(*n.typeID(), p.node.meta()), __LINE__);
    }
#endif
};

} // anonymous namespace

bool spicy::detail::ast::resolve(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_resolve)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/resolver");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified || hilti_modified;
}
