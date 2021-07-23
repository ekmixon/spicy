// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/builder/expression.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/base/logger.h>
#include <hilti/global.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/operators/all.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>

#include "base/optional-ref.h"

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using hilti::util::fmt;

namespace builder = hilti::builder;

namespace {

// Visitor that runs only once the 1st time AST transformation is triggered.
struct Visitor : public hilti::visitor::PreOrder<void, Visitor> {
    Visitor(CodeGen* cg, hilti::Module* module, bool first_pass) : cg(cg), module(module), first_pass(first_pass) {}
    CodeGen* cg;
    hilti::Module* module;
    ID module_id = ID("<no module>");
    bool first_pass = true;
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        p->node = std::forward<T>(n);
        modified = true;
    }

    void replaceNode(position_t* p, Node&& n) {
        if ( p->node.location() && ! n.location() ) {
            auto m = n.meta();
            m.setLocation(p->node.location());
            n.setMeta(std::move(m));
        }

        p->node = std::move(n);
        modified = true;
    }

    Expression argument(const Expression& args, unsigned int i, std::optional<Expression> def = {}) {
        auto ctor = args.as<hilti::expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        auto value = ctor.as<hilti::ctor::Tuple>().value();

        if ( i < value.size() )
            return ctor.as<hilti::ctor::Tuple>().value()[i];

        if ( def )
            return *def;

        hilti::logger().internalError(fmt("missing argument %d", i));
    }

    void operator()(const hilti::declaration::Property& m) { cg->recordModuleProperty(m); }

    void operator()(const hilti::Module& m) {
        if ( first_pass ) {
            module_id = m.id();
            cg->addDeclaration(builder::import("hilti", m.meta()));
            cg->addDeclaration(builder::import("spicy_rt", m.meta()));
        }
    }

    void operator()(const hilti::declaration::Type& t, position_t p) {
        // Replace unit type with compiled struct type.
        auto u = t.type().tryAs<type::Unit>();
        if ( ! u )
            return;

        // Build the unit's grammar.
        if ( auto r = cg->grammarBuilder()->run(*u, &p.node, cg); ! r ) {
            hilti::logger().error(r.error().description(), p.node.location());
            return;
        }

        auto ns = cg->compileUnit(*u, false);
        auto attrs = AttributeSet({Attribute("&on-heap")});
        auto nd = hilti::declaration::Type(t.id(), ns, attrs, t.linkage(), t.meta());
        replaceNode(&p, nd);
    }

    void operator()(const declaration::UnitHook& n, position_t p) {
        const auto& unit_type = n.unitType();
        const auto& hook = n.unitHook().hook();

        if ( ! unit_type )
            // Not resolved yet.
            return;

        auto func = cg->compileHook(*unit_type, ID(*unit_type->id(), n.unitHook().id()), {}, hook.isForEach(),
                                    hook.isDebug(), hook.ftype().parameters().copy<type::function::Parameter>(),
                                    hook.body(), hook.priority(), n.meta());

        replaceNode(&p, std::move(func));
    }

    void operator()(const hilti::expression::ResolvedID& n, position_t p) {
        // Re-resolve IDs.
        replaceNode(&p, hilti::expression::UnresolvedID(n.id(), p.node.meta()));
    }

    result_t operator()(const operator_::bitfield::Member& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        auto idx = n.op0().type().as<spicy::type::Bitfield>().bitsIndex(id);
        assert(idx);
        auto x = builder::index(n.op0(), *idx, n.meta());
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::Unset& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        replaceNode(&p, builder::unset(n.op0(), id, n.meta()));
    }

    result_t operator()(const operator_::unit::MemberConst& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        replaceNode(&p, builder::member(n.op0(), id, n.meta()));
    }

    result_t operator()(const operator_::unit::MemberNonConst& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        replaceNode(&p, builder::member(n.op0(), id, n.meta()));
    }

    result_t operator()(const operator_::unit::TryMember& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        replaceNode(&p, builder::tryMember(n.op0(), id, n.meta()));
    }

    result_t operator()(const operator_::unit::HasMember& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        replaceNode(&p, builder::hasMember(n.op0(), id, n.meta()));
    }

    result_t operator()(const operator_::unit::MemberCall& n, position_t p) {
        const auto& id = n.op1().as<hilti::expression::Member>().id();
        const auto& args = n.op2().as<hilti::expression::Ctor>().ctor().as<hilti::ctor::Tuple>();
        replaceNode(&p, builder::memberCall(n.op0(), id, args, n.meta()));
    }

    result_t operator()(const operator_::unit::Offset& n, position_t p) {
        auto begin = builder::deref(builder::member(n.op0(), ID("__begin")));
        auto cur = builder::deref(builder::member(n.op0(), ID("__position")));
        replaceNode(&p, builder::cast(builder::difference(cur, begin), type::UnsignedInteger(64)));
    }

    result_t operator()(const operator_::unit::Position& n, position_t p) {
        replaceNode(&p, builder::member(n.op0(), ID("__position")));
    }

    result_t operator()(const operator_::unit::Input& n, position_t p) {
        auto begin = builder::deref(builder::member(n.op0(), ID("__begin")));
        replaceNode(&p, begin);
    }

    result_t operator()(const operator_::unit::SetInput& n, position_t p) {
        auto cur = builder::member(n.op0(), ID("__position_update"));
        replaceNode(&p, builder::assign(cur, argument(n.op2(), 0)));
    }

    result_t operator()(const operator_::unit::Find& n, position_t p) {
        auto begin = builder::deref(builder::member(n.op0(), ID("__begin")));
        auto end = builder::deref(builder::member(n.op0(), ID("__position")));
        auto i = argument(n.op2(), 2, builder::null());
        auto needle = argument(n.op2(), 0);
        auto direction = argument(n.op2(), 1, builder::id("spicy::Direction::Forward"));
        auto x = builder::call("spicy_rt::unit_find", {begin, end, i, needle, direction});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::ContextConst& n, position_t p) {
        auto x = builder::member(n.op0(), ID("__context"));
        replaceNode(&p, x);
    }

    result_t operator()(const operator_::unit::ContextNonConst& n, position_t p) {
        auto x = builder::member(n.op0(), ID("__context"));
        replaceNode(&p, x);
    }

    result_t operator()(const operator_::unit::Backtrack& n, position_t p) {
        auto x = builder::call("spicy_rt::backtrack", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::ConnectFilter& n, position_t p) {
        auto x = builder::call("spicy_rt::filter_connect", {n.op0(), argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::Forward& n, position_t p) {
        auto x = builder::call("spicy_rt::filter_forward", {n.op0(), argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::ForwardEod& n, position_t p) {
        auto x = builder::call("spicy_rt::filter_forward_eod", {n.op0()});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Close& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "close", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Connect& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::ConnectMIMETypeBytes& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect_mime_type", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::ConnectMIMETypeString& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect_mime_type", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::ConnectFilter& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect_filter", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Gap& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "gap", {argument(n.op2(), 0), argument(n.op2(), 1)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SequenceNumber& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "sequence_number", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SetAutoTrim& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "set_auto_trim", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SetInitialSequenceNumber& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "set_initial_sequence_number", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SetPolicy& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "set_policy", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SizeValue& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "size", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SizeReference& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "size", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Skip& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "skip", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Trim& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "trim", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Write& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "write",
                                     {argument(n.op2(), 0), argument(n.op2(), 1, builder::null()),
                                      argument(n.op2(), 2, builder::null())});
        replaceNode(&p, std::move(x));
    }

    void operator()(const statement::Print& n, position_t p) {
        auto exprs = n.expressions().copy<Expression>();

        switch ( exprs.size() ) {
            case 0: {
                auto call = builder::call("hilti::print", {builder::string("")});
                replaceNode(&p, hilti::statement::Expression(call, p.node.location()));
                break;
            }

            case 1: {
                auto call = builder::call("hilti::print", std::move(exprs));
                replaceNode(&p, hilti::statement::Expression(call, p.node.location()));
                break;
            }

            default: {
                auto call = builder::call("hilti::printValues", {builder::tuple(std::move(exprs))});
                replaceNode(&p, hilti::statement::Expression(call, p.node.location()));
                break;
            }
        }
    }

    void operator()(const statement::Stop& n, position_t p) {
        auto b = builder::Builder(cg->context());
        b.addAssign(builder::id("__stop"), builder::bool_(true), n.meta());
        b.addReturn(n.meta());
        replaceNode(&p, b.block());
    }

    void operator()(const type::Sink& n, position_t p) {
        // Strong reference (instead of value reference) so that copying unit
        // instances doesn't copy the sink.
        auto sink = hilti::type::StrongReference(builder::typeByID("spicy_rt::Sink", n.meta()));
        replaceNode(&p, Type(sink));
    }

    void operator()(const type::Unit& n, position_t p) {
        // Replace usage of the the unit type with a reference to the compiled struct.
        if ( auto t = p.parent().tryAs<hilti::declaration::Type>();
             ! t && ! p.parent(2).tryAs<hilti::declaration::Type>() ) {
            assert(n.id());
            replaceNode(&p, hilti::type::UnresolvedID(*n.id(), p.node.meta()));
        }
    }
};


} // anonymous namespace

bool CodeGen::compileModule(hilti::Node* root, hilti::Unit* u) {
    hilti::util::timing::Collector _("spicy/compiler/codegen");

    _hilti_unit = u;
    _root = root;
    bool modified = false;

    while ( true ) {
        auto v = Visitor(this, &root->as<hilti::Module>(), ! modified);
        for ( auto i : v.walk(root) )
            v.dispatch(i);

        if ( ! hilti::logger().errors() ) {
            if ( _new_decls.size() ) {
                for ( const auto& n : _new_decls )
                    hiltiModule()->add(n);

                _new_decls.clear();
                modified = true;
            }
        }

        if ( ! v.modified )
            break;

        modified = true;
    }

    _hilti_unit = nullptr;
    _root = nullptr;

    return modified;
}

std::optional<hilti::declaration::Function> CodeGen::compileHook(
    const type::Unit& unit, const ID& id, std::optional<std::reference_wrapper<const type::unit::item::Field>> field,
    bool foreach, bool debug, std::vector<type::function::Parameter> params, std::optional<hilti::Statement> body,
    std::optional<Expression> priority, const hilti::Meta& meta) {
    if ( debug && ! options().debug )
        return {};

    bool is_container = false;
    std::optional<Type> original_field_type;

    if ( field ) {
        if ( ! field->get().parseType().isA<type::Void>() )
            original_field_type = field->get().originalType();

        is_container = field->get().isContainer();
    }
    else {
        // Try to locate field by ID.
        if ( auto f = unit.field(id.local()) ) {
            if ( ! f->parseType().isA<type::Void>() ) {
                is_container = f->isContainer();
                original_field_type = f->originalType();
            }
        }
    }

    if ( foreach ) {
        params.push_back(
            {ID("__dd"), field->get().parseType().elementType(), hilti::type::function::parameter::Kind::In, {}});
        params.push_back({ID("__stop"), type::Bool(), hilti::type::function::parameter::Kind::InOut, {}});
    }
    else if ( original_field_type ) {
        params.push_back({ID("__dd"), field->get().parseType(), hilti::type::function::parameter::Kind::In, {}});

        // Pass on captures for fields of type regexp, which are the only
        // ones they have it (for vector of regexps, it wouldn't be clear what
        // to bind to).
        if ( original_field_type->isA<type::RegExp>() && ! is_container )
            params.push_back({ID("__captures"),
                              builder::typeByID("hilti::Captures"),
                              hilti::type::function::parameter::Kind::In,
                              {}});
    }

    std::string hid;
    Type result;

    if ( id.local().str() == "0x25_print" ) {
        // Special-case: We simply translate this into HITLI's __str__ hook.
        result = hilti::type::Optional(hilti::type::String());
        hid = "__str__";
    }
    else {
        result = hilti::type::Void();
        hid = fmt("__on_%s%s", id.local(), (foreach ? "_foreach" : ""));
    }

    if ( ! id.namespace_().empty() )
        hid = fmt("%s::%s", id.namespace_(), hid);

    auto rt = hilti::type::function::Result(std::move(result));
    auto ft = hilti::type::Function(std::move(rt), params, hilti::type::function::Flavor::Hook, meta);

    std::optional<AttributeSet> attrs;

    if ( priority )
        attrs = AttributeSet::add(attrs, Attribute("&priority", *priority));

    auto f = hilti::Function(ID(hid), std::move(ft), std::move(body), hilti::function::CallingConvention::Standard,
                             std::move(attrs), meta);
    return hilti::declaration::Function(std::move(f), hilti::declaration::Linkage::Struct, meta);
}

hilti::Module* CodeGen::hiltiModule() const {
    if ( ! _hilti_unit )
        hilti::logger().internalError("not compiling a HILTI unit");

    return &_root->as<hilti::Module>();
}

hilti::Unit* CodeGen::hiltiUnit() const {
    if ( ! _hilti_unit )
        hilti::logger().internalError("not compiling a HILTI unit");

    return _hilti_unit;
}

NodeRef CodeGen::preserveNode(Expression x) { return hiltiModule()->preserve(std::move(x)); }

NodeRef CodeGen::preserveNode(Statement x) { return hiltiModule()->preserve(std::move(x)); }

NodeRef CodeGen::preserveNode(Type x) { return hiltiModule()->preserve(std::move(x)); }
