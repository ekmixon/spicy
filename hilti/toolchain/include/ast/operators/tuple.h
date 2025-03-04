// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/tuple.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_2(tuple, Equal, type::Bool(), type::constant(type::Tuple(type::Wildcard())),
                    operator_::sameTypeAs(0, "tuple<*>"), "Compares two tuples element-wise.");
STANDARD_OPERATOR_2(tuple, Unequal, type::Bool(), type::constant(type::Tuple(type::Wildcard())),
                    operator_::sameTypeAs(0, "tuple<*>"), "Compares two tuples element-wise.");

BEGIN_OPERATOR_CUSTOM(tuple, Index)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<type of element>");

        if ( ops.size() < 2 )
            return type::unknown;

        auto ctor = ops[1].tryAs<expression::Ctor>();
        if ( ! ctor )
            return type::unknown;

        auto i = ctor->ctor().tryAs<ctor::UnsignedInteger>();
        if ( ! i )
            return type::unknown;

        const auto& elements = ops[0].type().as<type::Tuple>().elements();

        if ( static_cast<uint64_t>(elements.size()) <= i->value() )
            return type::unknown;

        return elements[i->value()].type();
    }

    bool isLhs() const { return true; }

    std::vector<Operand> operands() const {
        return {{.type = type::Tuple(type::Wildcard())}, {.type = type::UnsignedInteger(64)}};
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        if ( auto ec = i.op1().tryAs<expression::Ctor>() )
            if ( auto c = ec->ctor().tryAs<ctor::UnsignedInteger>() ) {
                if ( c->value() < 0 ||
                     c->value() >= static_cast<uint64_t>(i.op0().type().as<type::Tuple>().elements().size()) )
                    p.node.addError("tuple index out of range");

                return;
            }

        p.node.addError("tuple index must be an integer constant");
    }

    std::string doc() const {
        return "Extracts the tuple element at the given index. The index must be a constant unsigned integer.";
    }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(tuple, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<type of element>");

        auto id = ops[1].as<expression::Member>().id();
        auto elem = ops[0].type().as<type::Tuple>().elementByID(id);
        if ( ! elem )
            return type::unknown;

        return elem->second->type();
    }

    bool isLhs() const { return true; }

    std::vector<Operand> operands() const {
        return {{.type = type::Tuple(type::Wildcard())}, {.type = type::Member(type::Wildcard()), .doc = "<id>"}};
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        auto id = i.operands()[1].as<expression::Member>().id();
        auto elem = i.operands()[0].type().as<type::Tuple>().elementByID(id);

        if ( ! elem )
            p.node.addError("unknown tuple element");
    }

    std::string doc() const { return "Extracts the tuple element corresponding to the given ID."; }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM(tuple, CustomAssign)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<tuple>");

        return ops[0].type();
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        // The operator gets instantiated only through the normalizer, but this is used for documentation.
        return {{
                    .type = type::Member(type::Wildcard()),
                    .doc = "(x, ..., y)",
                },
                {.type = type::Tuple(type::Wildcard()), .doc = "<tuple>"}};
        return {};
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        auto lhs = i.operands()[0].as<expression::Ctor>().ctor().as<ctor::Tuple>();
        auto lhs_type = lhs.type().as<type::Tuple>();
        auto rhs_type = i.operands()[1].type().tryAs<type::Tuple>();
        if ( ! rhs_type ) {
            p.node.addError("rhs is not a tuple");
            return;
        }

        if ( lhs_type.elements().size() != rhs_type->elements().size() ) {
            p.node.addError("cannot assign tuples of different length");
            return;
        }

        for ( auto i = 0u; i < lhs_type.elements().size(); i++ ) {
            const auto& lhs_elem = lhs.value()[i];
            const auto& lhs_elem_type = lhs_type.elements()[i].type();
            const auto& rhs_elem_type = rhs_type->elements()[i].type();

            if ( ! lhs_elem.isLhs() )
                p.node.addError(util::fmt("cannot assign to expression: %s", to_node(lhs_elem)));

            if ( ! type::sameExceptForConstness(lhs_elem_type, rhs_elem_type) )
                p.node.addError(util::fmt("type mismatch for element %d in assignment, expected type %s but got %s", i,
                                          lhs_elem_type, rhs_elem_type));
        }
    }

    std::string doc() const { return "Assigns element-wise to the left-hand-side tuple"; }
END_OPERATOR_CUSTOM_x

} // namespace operator_
} // namespace hilti
