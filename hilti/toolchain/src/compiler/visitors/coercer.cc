// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/all.h>
#include <hilti/ast/builder/expression.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>
#include <hilti/global.h>

using namespace hilti;
using util::fmt;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Coercer("coercer");
} // namespace hilti::logging::debug

namespace {

struct Visitor : public visitor::PreOrder<void, Visitor> {
    Visitor(Unit* unit) : unit(unit) {}
    Unit* unit;
    bool modified = false;

#if 0
    void preDispatch(const Node& n, int level) override {
        auto indent = std::string(level * 2, ' ');
        std::cerr << "# " << indent << "> " << n.render() << std::endl;
        n.scope()->render(std::cerr, "    | ");
    };
#endif
    // Log debug message recording updating attributes.
    void logChange(const Node& old, const Node& new_, const char* desc) {
        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, desc, new_, old.location()));
    }

    /** Returns a method call's i-th argument. */
    const Expression& methodArgument(const expression::ResolvedOperatorBase& o, size_t i) {
        auto ops = o.op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops.tryAs<expression::Coerced>() )
            ops = coerced->expression();

        if ( auto ctor_ = ops.tryAs<expression::Ctor>() ) {
            auto ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto x = ctor.tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto args = ctor.tryAs<ctor::Tuple>(); args && i < args->value().size() )
                return args->value()[i];
        }

        util::cannot_be_reached();
    }

    /**
     * Coerces an expression to a given type, return the new value if it's
     * changed from the the old one. Records an error with the node if coercion
     * is not possible. Will indicate no-chage if expression or type hasn't
     * been resolved.
     **/
    std::optional<Expression> coerceTo(Node* n, const Expression& e, const Type& t, bool contextual, bool assignment) {
        if ( ! (expression::isResolved(e) && type::isResolved(t)) )
            return {};

        if ( e.type() == t )
            return {};

        bitmask<CoercionStyle> style =
            (assignment ? CoercionStyle::TryAllForAssignment : CoercionStyle::TryAllForMatching);

        if ( contextual )
            style |= CoercionStyle::ContextualConversion;

        if ( auto c = hilti::coerceExpression(e, t, style) )
            return c.nexpr;

        n->addError(fmt("cannot coerce expression '%s' of type '%s' to type '%s'", e, e.type(), t));
        return {};
    }

    template<typename Container1, typename Container2>
    Result<std::optional<std::vector<Expression>>> coerceCallArguments(Container1 exprs, Container2 params) {
        // Build a tuple to coerce expression according to an OperandList.

        if ( ! expression::isResolved(exprs) )
            return {std::nullopt};

        auto src = expression::Ctor(ctor::Tuple(std::move(exprs)));
        auto dst = type::OperandList::fromParameters(std::move(params));

        auto coerced = coerceExpression(src, type::constant(dst), CoercionStyle::TryAllForFunctionCall);
        if ( ! coerced )
            return result::Error("coercion failed");

        if ( ! coerced.nexpr )
            // No change.
            return {std::nullopt};

        return {coerced.nexpr->template as<expression::Ctor>()
                    .ctor()
                    .template as<ctor::Tuple>()
                    .value()
                    .template copy<Expression>()};
    }

    // Will do nothing if expressions or type aren't resolved.
    template<typename Container>
    Result<std::optional<std::vector<Expression>>> coerceExpressions(const Container& exprs, const Type& dst) {
        if ( ! type::isResolved(dst) )
            return {std::nullopt};

        for ( const auto& e : exprs ) {
            if ( ! expression::isResolved(e) )
                return {std::nullopt};
        }

        bool changed = false;
        std::vector<Expression> nexprs;

        for ( const auto& e : exprs ) {
            auto coerced = coerceExpression(e, type::constant(dst), CoercionStyle::TryAllForAssignment);
            if ( ! coerced )
                return result::Error("coercion failed");

            if ( coerced.nexpr )
                changed = true;

            nexprs.emplace_back(std::move(*coerced.coerced));
        }

        if ( changed )
            return {std::move(nexprs)};
        else
            // No change.
            return {std::nullopt};
    }

    void operator()(const Attribute& n) {
        // TODO(robin): Coerce attributes with expressions.
    }

    void operator()(const ctor::List& n, position_t p) {
        if ( auto coerced = coerceExpressions(n.value(), n.elementType()) ) {
            if ( *coerced ) {
                logChange(p.node, ctor::Tuple(**coerced), "elements");
                p.node.as<ctor::List>().setValue(std::move(**coerced));
                modified = true;
            }
        }
        else {
            if ( n.type().elementType() != type::unknown )
                p.node.addError("type mismatch in list elements");
        }
    }

    void operator()(const ctor::Map& n, position_t p) {
        if ( ! (type::isResolved(n.keyType()) && type::isResolved(n.valueType())) )
            return;

        for ( const auto& e : n.value() ) {
            if ( ! (expression::isResolved(e.key()) && expression::isResolved(e.value())) )
                return;
        }

        bool changed = false;

        std::vector<ctor::map::Element> nelems;
        for ( const auto& e : n.value() ) {
            auto k = coerceExpression(e.key(), n.keyType());
            if ( ! k ) {
                p.node.addError("type mismatch in map keys");
                return;
            }

            auto v = coerceExpression(e.value(), n.valueType());
            if ( ! v ) {
                p.node.addError("type mismatch in map values");
                return;
            }

            if ( k.nexpr || v.nexpr ) {
                nelems.emplace_back(*k.coerced, *v.coerced);
                changed = true;
            }
            else
                nelems.push_back(e);
        }

        if ( changed ) {
            logChange(p.node, ctor::Map(nelems), "value");
            p.node.as<ctor::Map>().setValue(std::move(nelems));
            modified = true;
        }
    }

    void operator()(const ctor::Set& n, position_t p) {
        auto coerced = coerceExpressions(n.value(), n.elementType());
        if ( ! coerced )
            p.node.addError("type mismatch in set elements");
        else if ( *coerced ) {
            logChange(p.node, ctor::Tuple(**coerced), "value");
            p.node.as<ctor::Set>().setValue(std::move(**coerced));
            modified = true;
        }
    }

    void operator()(const ctor::Vector& n, position_t p) {
        auto coerced = coerceExpressions(n.value(), n.elementType());
        if ( ! coerced )
            p.node.addError("type mismatch in vector elements");
        else if ( *coerced ) {
            logChange(p.node, ctor::Tuple(**coerced), "value");
            p.node.as<ctor::Vector>().setValue(std::move(**coerced));
            modified = true;
        }
    }

    void operator()(const ctor::Default& n, position_t p) {
        if ( ! type::isResolved(n.type()) )
            return;

        auto t = n.type();

        if ( auto vr = t.tryAs<type::ValueReference>() )
            t = vr->dereferencedType();

        if ( type::takesArguments(t) ) {
            if ( auto x = n.typeArguments(); x.size() ) {
                if ( auto coerced = coerceCallArguments(x, t.parameters()); coerced && *coerced ) {
                    logChange(p.node, ctor::Tuple(**coerced), "call arguments");
                    p.node.as<ctor::Default>().setTypeArguments(std::move(**coerced));
                    modified = true;
                }
            }
        }
    }

    void operator()(const declaration::Constant& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.value(), n.type(), false, true) ) {
            logChange(p.node, *x, "value");
            p.node.as<declaration::Constant>().setValue(std::move(*x));
            modified = true;
        }
    }

    void operator()(const declaration::Parameter& n, position_t p) {
        if ( auto def = n.default_() ) {
            if ( auto x = coerceTo(&p.node, *def, n.type(), false, true) ) {
                logChange(p.node, *x, "default value");
                p.node.as<declaration::Parameter>().setDefault(std::move(*x));
                modified = true;
            }
        }
    }

    void operator()(const declaration::LocalVariable& n, position_t p) {
        std::optional<Expression> init;
        std::optional<std::vector<Expression>> args;

        if ( auto e = n.init() ) {
            if ( auto x = coerceTo(&p.node, *e, n.type(), false, true) )
                init = std::move(*x);
        }

        if ( type::takesArguments(n.type()) && n.typeArguments().size() ) {
            auto coerced = coerceCallArguments(n.typeArguments(), n.type().parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                logChange(p.node, *init, "init expression");
                p.node.as<declaration::LocalVariable>().setInit(std::move(*init));
            }

            if ( args ) {
                logChange(p.node, ctor::Tuple(*args), "type arguments");
                p.node.as<declaration::LocalVariable>().setTypeArguments(std::move(*args));
            }

            modified = true;
        }
    }

    void operator()(const declaration::GlobalVariable& n, position_t p) {
        std::optional<Expression> init;
        std::optional<std::vector<Expression>> args;

        if ( auto e = n.init() ) {
            if ( auto x = coerceTo(&p.node, *e, n.type(), false, true) )
                init = std::move(*x);
        }

        if ( type::takesArguments(n.type()) && n.typeArguments().size() ) {
            auto coerced = coerceCallArguments(n.typeArguments(), n.type().parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                logChange(p.node, *init, "init expression");
                p.node.as<declaration::GlobalVariable>().setInit(std::move(*init));
            }

            if ( args ) {
                logChange(p.node, ctor::Tuple(*args), "type arguments");
                p.node.as<declaration::GlobalVariable>().setTypeArguments(std::move(*args));
            }

            modified = true;
        }
    }

    void operator()(const operator_::generic::New& n, position_t p) {
        auto etype = n.op0().tryAs<expression::Type_>();
        if ( ! etype )
            return;

        if ( type::takesArguments(etype->typeValue()) ) {
            auto args = n.op1().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
            if ( auto coerced = coerceCallArguments(args, etype->typeValue().parameters()); coerced && *coerced ) {
                Expression ntuple = expression::Ctor(ctor::Tuple(**coerced), n.op1().meta());
                logChange(p.node, ntuple, "type arguments");
                p.node.as<operator_::generic::New>().setOp1(std::move(ntuple));
                modified = true;
            }
        }
    }

    void operator()(const operator_::vector::PushBack& n, position_t p) {
        // Need to coerce the element here as the normal overload resolution
        // couldn't know the element type yet.
        auto etype = type::effectiveType(n.op0().type()).as<type::Vector>().elementType();
        auto elem = methodArgument(n, 0);

        if ( auto x = coerceTo(&p.node, n.op2(), type::Tuple({etype}), false, true) ) {
            logChange(p.node, *x, "element type");
            p.node.as<operator_::vector::PushBack>().setOp2(std::move(*x));
            modified = true;
        }
    }

    void operator()(const statement::Assert& n, position_t p) {
        if ( n.expectsException() )
            return;

        if ( auto x = coerceTo(&p.node, n.expression(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "expression");
            p.node.as<statement::Assert>().setCondition(std::move(*x));
            modified = true;
        }
    }

    void operator()(const statement::If& n, position_t p) {
        if ( auto cond = n.condition() ) {
            if ( auto x = coerceTo(&p.node, *cond, type::Bool(), true, false) ) {
                logChange(p.node, *x, "condition");
                p.node.as<statement::If>().setCondition(std::move(*x));
                modified = true;
            }
        }
    }

    void operator()(const statement::Return& n, position_t p) {
        auto func = p.findParent<Function>();
        if ( ! func ) {
            p.node.addError("return outside of function");
            return;
        }

        auto e = n.expression();
        if ( ! e )
            return;

        const auto& t = func->get().ftype().result().type();

        if ( auto x = coerceTo(&p.node, *e, t, false, true) ) {
            logChange(p.node, *x, "expression");
            p.node.as<statement::Return>().setExpression(std::move(*x));
            modified = true;
        }
    }

    void operator()(const statement::While& n, position_t p) {
        if ( auto cond = n.condition() ) {
            if ( auto x = coerceTo(&p.node, *cond, type::Bool(), true, false) ) {
                logChange(p.node, *x, "condition");
                p.node.as<statement::While>().setCondition(std::move(*x));
                modified = true;
            }
        }
    }

    void operator()(const type::struct_::Field& f, position_t p) {
        if ( auto a = f.attributes() ) {
            AttributeSet attrs = *a;
            if ( auto x = attrs.coerceValueTo("&default", f.type()) ) {
                if ( *x ) {
                    logChange(p.node, attrs, "attributes");
                    p.node.as<type::struct_::Field>().setAttributes(std::move(attrs));
                    modified = true;
                }

                return;
            }
            else
                p.node.addError(fmt("cannot coerce default expression to type '%s'", f.type()));
        }
    }

    void operator()(const expression::Assign& n, position_t p) {
        // We allow assignments from const to non-const here, assignment
        // is by value.
        if ( auto x = coerceTo(&p.node, n.source(), n.target().type(), false, true) ) {
            logChange(p.node, *x, "source");
            p.node.as<expression::Assign>().setSource(std::move(*x));
            modified = true;
        }
    }

    void operator()(const expression::BuiltinFunction& n, position_t p) {
        if ( auto coerced = coerceCallArguments(n.arguments(), n.parameters()); coerced && *coerced ) {
            logChange(p.node, ctor::Tuple(**coerced), "call arguments");
            p.node.as<expression::BuiltinFunction>().setArguments(std::move(**coerced));
            modified = true;
        }
    }

    void operator()(const expression::LogicalAnd& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.op0(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op0");
            p.node.as<expression::LogicalAnd>().setOp0(std::move(*x));
            modified = true;
        }

        if ( auto x = coerceTo(&p.node, n.op1(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op1");
            p.node.as<expression::LogicalAnd>().setOp1(std::move(*x));
            modified = true;
        }
    }

    void operator()(const expression::LogicalNot& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.expression(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "expression");
            p.node.as<expression::LogicalNot>().setExpression(std::move(*x));
            modified = true;
        }
    }

    void operator()(const expression::LogicalOr& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.op0(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op0");
            p.node.as<expression::LogicalOr>().setOp0(std::move(*x));
            modified = true;
        }

        if ( auto x = coerceTo(&p.node, n.op1(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op1");
            p.node.as<expression::LogicalOr>().setOp1(std::move(*x));
            modified = true;
        }
    }

    void operator()(const expression::PendingCoerced& pc, position_t p) {
        if ( auto ner = hilti::coerceExpression(pc.expression(), pc.type()); ner.coerced ) {
            if ( ner.nexpr ) {
                // A coercion expression was created, use it.
                p.node = *ner.nexpr;
                modified = true;
            }
            else {
                // Coercion not needed, use original expression.
                p.node = pc.expression();
                modified = true;
            }
        }
        else
            p.node.addError(fmt("cannot coerce expression '%s' to type '%s'", pc.expression(), pc.type()));
    }
};

} // anonymous namespace

bool hilti::detail::ast::coerce(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/ast/coerce");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified;
}
