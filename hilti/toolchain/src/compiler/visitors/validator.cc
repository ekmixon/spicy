// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <unordered_set>

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/module.h>
#include <hilti/ast/types/function.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/global.h>

#include "ast/node.h"

using namespace hilti;
using util::fmt;

namespace {

struct Visitor : public visitor::PostOrder<void, Visitor> {
    // Record error at location of current node.
    void error(std::string msg, position_t& p, node::ErrorPriority priority = node::ErrorPriority::Normal) {
        p.node.addError(msg, p.node.location(), priority);
        ++errors;
    }

    // Record error with current node, but report with another node's location.
    void error(std::string msg, position_t& p, const Node& n,
               node::ErrorPriority priority = node::ErrorPriority::Normal) {
        p.node.addError(msg, n.location(), priority);
        ++errors;
    }

    // Record error with current node, but report with a custom location.
    void error(std::string msg, position_t& p, Location l, node::ErrorPriority priority = node::ErrorPriority::Normal) {
        p.node.addError(msg, std::move(l), priority);
        ++errors;
    }

    int errors = 0;

    void preDispatch(const Node& n, int level) override {
        // Validate that identifier names are not reused.
        for ( const auto& [id, nodes] : n.scope()->items() ) {
            if ( nodes.size() <= 1 )
                continue;

            const auto& firstNode = nodes.front();
            for ( auto it = std::next(nodes.begin()); it != nodes.end(); ++it ) {
                const auto& node = *it;

                // We whitelist functions and import declarations as they can legitimately appear multiple times.
                // To not permit shadowing of e.g., variable declarations with function declarations, we require nodes
                // with identical names to have identical types unless we are in an `ImportedModule` declaration
                // referring to a previously declared `Module` of the same name.
                if ( node->isA<declaration::Function>() && node->typeid_() == firstNode->typeid_() )
                    continue;
                else if ( node->isA<declaration::ImportedModule>() &&
                          (node->typeid_() == firstNode->typeid_() || firstNode->isA<declaration::Module>()) )
                    continue;

                // TODO: Should make preDispatch() recevie a non-const node
                // so that we can set errors here.
                logger().error(fmt("redefinition of '%s' defined in %s", id, firstNode->location()), node->location());
            }
        }
    };

    void operator()(const Function& f, position_t p) {
        if ( auto attrs = f.attributes() ) {
            if ( auto prio = attrs->find("&priority") ) {
                if ( f.ftype().flavor() != type::function::Flavor::Hook )
                    error("only hooks can have priorities", p);

                else if ( auto x = prio->valueAsInteger(); ! x )
                    error(x.error(), p);
            }
        }
    }

    ////// Declarations

    void operator()(const declaration::Constant& n, position_t p) {
        if ( n.value().type().isWildcard() )
            error("cannot use wildcard type for constants", p);
    }

    void operator()(const declaration::LocalVariable& n, position_t p) {
        if ( ! type::isAllocable(n.type()) )
            error(fmt("type '%s' cannot be used for variable declaration", n.type()), p);

        if ( n.type().isWildcard() )
            error("cannot use wildcard type for variables", p);

        if ( ! n.typeArguments().empty() ) {
            auto t = n.type();

            if ( type::isReferenceType(t) )
                t = t.dereferencedType();

            if ( ! t.isA<type::Struct>() )
                error("only struct types can have arguments", p);
        }

        if ( auto st = n.type().tryAs<type::Struct>() )
            _checkStructArguments(n.typeArguments(), st->parameters(), p);

        // Check whether this local variable was declared at module scope. We
        // need to match exact parent nodes here to not match other locals
        // three levels under a `Module` (e.g., a local in a `while` statement
        // at module scope).
        if ( p.pathLength() > 3 && p.parent(1).isA<statement::Declaration>() && p.parent(2).isA<statement::Block>() &&
             p.parent(3).isA<Module>() )
            error("local variables cannot be declared at module scope", p);
    }

    void operator()(const declaration::Parameter& n, position_t p) {
        if ( ! n.type().isA<type::Auto>() ) {
            if ( ! type::isAllocable(n.type()) && type::nonConstant(n.type()) != type::Any() )
                error(fmt("type '%s' cannot be used for function parameter", n.type()), p);
        }

        if ( n.type().isWildcard() ) {
            if ( auto d = p.parent(3).tryAs<declaration::Function>() ) {
                if ( ! AttributeSet::find(d->function().attributes(), "&cxxname") )
                    error(fmt("parameter '%s' cannot have wildcard type; only allowed with runtime library "
                              "functions declared with &cxxname",
                              n.id()),
                          p);
            }

            if ( auto d = p.parent(4).tryAs<declaration::Type>() ) {
                if ( ! AttributeSet::find(d->attributes(), "&cxxname") )
                    error(fmt("parameter '%s' cannot have wildcard type; only allowed with methods in runtime "
                              "library structs declared with &cxxname",
                              n.id()),
                          p);
            }
        }
    }

    void operator()(const declaration::GlobalVariable& n, position_t p) {
        if ( ! type::isAllocable(n.type()) )
            error(fmt("type '%s' cannot be used for variable declaration", n.type()), p);

        if ( n.type().isWildcard() )
            error("cannot use wildcard type for variables", p);

        if ( auto args = n.typeArguments(); args.size() ) {
            if ( ! n.type().isA<type::Struct>() )
                error("only struct types can have arguments", p);
        }

        if ( auto st = n.type().tryAs<type::Struct>() )
            _checkStructArguments(n.typeArguments(), st->parameters(), p);
    }

    ////// Ctors

    void operator()(const ctor::Default& c, position_t p) {
        auto t = c.type();

        if ( auto vr = t.tryAs<type::ValueReference>() )
            t = vr->dereferencedType();

        if ( auto st = t.tryAs<type::Struct>() )
            _checkStructArguments(c.typeArguments(), st->parameters(), p);
    }

    void operator()(const hilti::ctor::Exception& e, position_t p) {
        if ( auto x = e.value().tryAs<hilti::expression::Ctor>() )
            if ( ! x->type().isA<type::String>() )
                error("exceptions need to be a string", p);
    }

    void operator()(const ctor::List& n, position_t p) {
        if ( ! n.value().empty() && n.elementType() == type::unknown ) {
            // List constructors are often used to initialize other elements,
            // and those may coerce them into the right type even if the
            // elements aren't consistent. We assume we are all good in that
            // case.
            if ( auto c = p.parent().tryAs<ctor::Coerced>(); ! c || c->type() == type::unknown )
                error("list elements have inconsistent types", p);
        }
    }

    void operator()(const ctor::Map& n, position_t p) {
        if ( ! n.value().empty() && (n.keyType() == type::unknown || n.valueType() == type::unknown) )
            error("map elements have inconsistent types", p);
    }

    void operator()(const ctor::Null& c, position_t p) {}

    void operator()(const ctor::SignedInteger& n, position_t p) {
        auto [min, max] = util::signed_integer_range(n.width());

        if ( n.value() < min || n.value() > max )
            error("integer value out of range for type", p);
    }

    void operator()(const ctor::Set& n, position_t p) {
        if ( ! n.value().empty() && n.elementType() == type::unknown )
            error("set elements have inconsistent types", p);
    }

    void operator()(const ctor::Struct& n, position_t p) {
        // TODO(robin): .
    }

    void operator()(const ctor::UnsignedInteger& n, position_t p) {
        auto [min, max] = util::unsigned_integer_range(n.width());

        if ( n.value() < min || n.value() > max )
            error("integer value out of range for type", p);
    }

    void operator()(const ctor::Vector& n, position_t p) {
        if ( ! n.value().empty() && n.elementType() == type::unknown )
            error("vector elements have inconsistent types", p);
    }

    ////// Expressions

    void operator()(const expression::Assign& n, position_t p) {
        if ( ! n.target().isLhs() )
            error(fmt("cannot assign to expression: %s", to_node(n)), p);

        if ( ! p.node.hasErrors() ) { // no need for more checks if coercer has already flagged it
            if ( ! type::sameExceptForConstness(n.source().type(), n.target().type()) )
                error(fmt("type mismatch for assignment, expected type %s but got %s", n.target().type(),
                          n.source().type()),
                      p);
        }
    }

    void operator()(const expression::ListComprehension& n, position_t p) {
        if ( ! type::isIterable(n.input().type()) )
            error("input value not iterable", p);
    }

    void operator()(const expression::Ternary& n, position_t p) {
        if ( ! hilti::type::sameExceptForConstness(n.true_().type(), n.false_().type()) )
            error(fmt("types of alternatives do not match in ternary expression (%s vs. %s)", n.true_().type(),
                      n.false_().type()),
                  p);
    }

    void operator()(const expression::UnresolvedID& n, position_t p) {
        if ( auto decl = p.findParent<Declaration>(); decl && ! decl->get().isA<declaration::Function>() ) {
            if ( n.id() == decl->get().id() )
                error("ID cannot be used inside its own declaration", p);
        }

        // We prefer the error message from a parent UnresolvedOperator.
        if ( ! p.node.hasErrors() && ! p.parent().isA<expression::UnresolvedOperator>() )
            error("unresolved ID", p);
    }

    ////// Statements

    void operator()(const statement::For& n, position_t p) {
        if ( ! type::isIterable(n.sequence().type()) )
            error("value not iterable", p);
    }

    void operator()(const statement::If& n, position_t p) {
        if ( ! (n.init() || n.condition()) )
            error("'if' header lacking both condition and declaration", p);
    }

    void operator()(const statement::Break& n, position_t p) {
        auto w = p.findParent<statement::While>();
        auto f = p.findParent<statement::For>();

        if ( ! (f || w) ) {
            error("'break' outside of loop", p);
            return;
        }
    }

    void operator()(const statement::Continue& n, position_t p) {
        auto w = p.findParent<statement::While>();
        auto f = p.findParent<statement::For>();

        if ( ! (f || w) ) {
            error("'continue' outside of loop", p);
            return;
        }
    }

    void operator()(const statement::Return& n, position_t p) {
        auto func = p.findParent<Function>();

        if ( ! func ) {
            error("'return' outside of function", p);
            return;
        }

        if ( func->get().ftype().result().type() == type::Void() ) {
            if ( n.expression() )
                error("void function cannot return a value", p);
        }
        else {
            if ( ! n.expression() )
                error("function must return a value", p);
        }
    }

    void operator()(const statement::Switch& n, position_t p) {}

    void operator()(const statement::Throw& n, position_t p) {
        if ( auto e = n.expression() ) {
            if ( ! e->type().isA<type::Exception>() )
                error("'throw' argument must be an exception", p);
        }
        else {
            if ( ! p.findParent<statement::try_::Catch>() )
                error("'throw' without expression can only be inside 'catch'", p);
        }
    }

    void operator()(const statement::try_::Catch& n, position_t p) {
        if ( n.parameter() && ! n.parameter()->type().isA<type::Exception>() )
            error("type of catch parameter must be an exception", p);
    }

    void operator()(const statement::Try& n, position_t p) {
        if ( n.catches().empty() ) {
            error("'try' statement without any 'catch'", p);
            return;
        }

        auto defaults = 0;

        for ( const auto& c : n.catches() ) {
            if ( ! c.parameter() )
                ++defaults;
        }

        if ( defaults > 1 )
            error("'try` statement cannot have more than one defaullt `catch`", p);
    }

    void operator()(const statement::While& n, position_t p) {
        if ( ! (n.init() || n.condition()) )
            error("'while' header lacking both condition and declaration", p);
    }

    void operator()(const expression::ResolvedOperator& n, position_t p) {
        // We are running after both overload resolution and the
        // apply-coercion pass, so operands types are ensured to be fine at
        // this point, so only need to run operator-specific validation.
        n.operator_().validate(n, p);
    }

    void operator()(const expression::UnresolvedOperator& n, position_t p) {
        if ( p.node.errors().empty() )
            error(fmt("unsupported operator: %s", hilti::detail::renderOperatorInstance(n)), p);
    }

    ////// Types

    void operator()(const type::Auto& n, position_t p) {
        error("automatic type has not been resolved", p, node::ErrorPriority::Low);
    }

    void operator()(const type::Exception& n, position_t p) {
        if ( n.baseType() && ! n.baseType()->isA<type::Exception>() )
            error("exception's base type must be an exception type as well", p);
    }

    void operator()(const type::Function& n, position_t p) {
        if ( n.flavor() == type::function::Flavor::Hook ) {
            auto r = n.result().type();
            if ( ! (r == type::Void() || r.isA<type::Optional>()) )
                error(fmt("hooks must have return type either void or optional<T>"), p);
        }
    }

    void operator()(const expression::Keyword& n, position_t p) {
        switch ( n.kind() ) {
            case expression::keyword::Kind::DollarDollar:
                if ( const auto& function = p.findParent<Function>() ) {
                    for ( const auto& hook : function->get().childsOfType<type::Function>() ) {
                        if ( hook.flavor() != type::function::Flavor::Hook )
                            continue;

                        const auto& parameters = hook.parameters();
                        if ( parameters.end() == std::find_if(parameters.begin(), parameters.end(),
                                                              [](auto&& p) { return p.id() == ID("__dd"); }) )
                            error("$$ is not available in this hook", p);
                    }
                    break;
                }

            case expression::keyword::Kind::Captures:
            case expression::keyword::Kind::Self:
                // Nothing.
                break;
        }
    }

    void operator()(const type::SignedInteger& n, position_t p) {
        auto w = n.width();

        if ( w != 8 && w != 16 && w != 32 && w != 64 && ! n.isWildcard() )
            error(fmt("integer type's width must be one of 8/16/32/64, but is %d", n.width()), p);
    }

    void operator()(const type::UnsignedInteger& n, position_t p) {
        auto w = n.width();

        if ( w != 8 && w != 16 && w != 32 && w != 64 && ! n.isWildcard() )
            error(fmt("integer type's width must be one of 8/16/32/64, but is %d", n.width()), p);
    }

    void operator()(const type::Optional& n, position_t p) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            error(fmt("type %s cannot be used inside optional", t), p);
    }

    void operator()(const type::StrongReference& n, position_t p) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            error(fmt("type %s is not allocable and can thus not be used with references", t), p);
    }

    void operator()(const type::Result& n, position_t p) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            error(fmt("type %s cannot be used inside result", t), p);
    }

    void operator()(const type::Struct& n, position_t p) {
        std::set<ID> seen;

        for ( const auto& f : n.fields() ) {
            if ( seen.find(f.id()) != seen.end() && ! f.type().isA<type::Function>() )
                error("duplicate attribute in struct type", p);

            seen.insert(f.id());

            if ( f.isStatic() && f.default_() )
                error("&default is currently not supported for static fields", p);

            if ( auto d = f.default_(); d && d->type() != f.type() )
                error(fmt("type mismatch for &default expression, expecting type %s", f.type()), p);

            if ( f.id().str() == "~finally" ) {
                auto ft = f.type().tryAs<type::Function>();
                if ( ! ft ) {
                    error("~finally must be a hook", p);
                    continue;
                }

                if ( ft->flavor() != type::function::Flavor::Hook )
                    error("~finally must be a hook", p);

                if ( ! ft->result().type().isA<type::Void>() )
                    error("~finally must have return type void", p);

                if ( ft->parameters().size() )
                    error("~finally cannot take any parameters", p);
            }
        }

        for ( const auto& param : n.parameters() ) {
            switch ( param.kind() ) {
                case declaration::parameter::Kind::Copy:
                case declaration::parameter::Kind::In:
                    // Nothing to check.
                    break;

                case declaration::parameter::Kind::InOut:
                    if ( ! type::isReferenceType(param.type()) )
                        error("only parameters of reference type can be 'inout' for struct parameters", p);
                    break;

                case declaration::parameter::Kind::Unknown: error("parameter kind unexpectedly not known", p); break;
            }
        }
    }

    void operator()(const type::Union& n, position_t p) {
        std::set<ID> seen;

        for ( const auto& f : n.fields() ) {
            if ( seen.find(f.id()) != seen.end() )
                error("duplicate attribute in union type", p);

            seen.insert(f.id());
        }
    }

    void operator()(const type::Tuple& n, position_t p) {
        for ( const auto& e : n.elements() ) {
            if ( ! type::isAllocable(e.type()) )
                error(fmt("type '%s' cannot be used inside a tuple", e.type()), p);
        }
    }

    void operator()(const type::UnresolvedID& n, position_t p) {
        if ( ! p.node.hasErrors() )
            error(fmt("unknown ID '%s'", n.id()), p, node::ErrorPriority::Low);
    }

    void operator()(const type::WeakReference& n, position_t p) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            error(fmt("type %s is not allocable and can thus not be used with weak references", t), p);
    }

    // Operators (only special cases here, most validation happens where they are defined)

    void operator()(const operator_::generic::New& n, position_t p) {
        // We reuse the _checkStructArguments() here, that's why this operator is covered here.
        if ( auto t = n.operands()[0].type().tryAs<type::Type_>() ) {
            if ( auto st = t->typeValue().tryAs<type::Struct>() ) {
                node::range<Expression> args;
                if ( n.operands().size() > 1 ) {
                    auto ctor = n.operands()[1].as<expression::Ctor>().ctor();
                    if ( auto x = ctor.tryAs<ctor::Coerced>() )
                        ctor = x->coercedCtor();

                    args = ctor.as<ctor::Tuple>().value();
                }

                _checkStructArguments(args, st->parameters(), p);
            }
        }
    }

    void _checkStructArguments(const node::range<Expression>& have, const node::set<type::function::Parameter>& want,
                               position_t& p) {
        if ( have.size() > want.size() )
            error(fmt("type expects %u parameter%s, but receives %u", have.size(), (have.size() > 1 ? "s" : ""),
                      want.size()),
                  p);

        for ( size_t i = 0; i < want.size(); i++ ) {
            if ( i < have.size() ) {
                if ( have[i].type() != want[i].type() )
                    error(fmt("type expects %s for parameter %u, but receives %s", want[i].type(), i + 1,
                              have[i].type()),
                          p);
            }
            else if ( ! want[i].default_() )
                error(fmt("type parameter %u is missing (%s)", i + 1, want[i].id()), p);
        }
    }
};

} // anonymous namespace

bool hilti::detail::ast::validate(Node* root) {
    util::timing::Collector _("hilti/compiler/ast/validator");

    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return false;
}
