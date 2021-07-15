// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/ast/types/doc-only.h>
#include <hilti/ast/types/operand-list.h>

/** Internal helper macro. */
#define __BEGIN_OPERATOR_CUSTOM(ns, op, cls)                                                                           \
    namespace ns {                                                                                                     \
    /** AST node for a the operator expression. */                                                                     \
    class cls : public hilti::expression::ResolvedOperatorBase {                                                       \
    public:                                                                                                            \
        using hilti::expression::ResolvedOperatorBase::ResolvedOperatorBase;                                           \
                                                                                                                       \
        /** Class implementing operator interface. */                                                                  \
        struct Operator : public hilti::trait::isOperator {                                                            \
            static ::hilti::operator_::Kind kind() { return ::hilti::operator_::Kind::op; }                            \
                                                                                                                       \
            hilti::Expression instantiate(const std::vector<hilti::Expression>& operands, const Meta& meta) const;     \
            std::string docNamespace() const { return #ns; }

/** Internal helper macro. */
#define __END_OPERATOR_CUSTOM                                                                                          \
    }                                                                                                                  \
    ;                                                                                                                  \
                                                                                                                       \
private:                                                                                                               \
    }                                                                                                                  \
    ;                                                                                                                  \
    }

/**
 * Starts definition of an operator. This macro is for the simple case where
 * the return type is static and no custom validation is needed.
 *
 * @param ns namespace to define the operator in
 * @param op ``operator_::Kind`` for the operator
 */
#define BEGIN_OPERATOR(ns, op) __BEGIN_OPERATOR_CUSTOM(ns, op, op)

/** Ends definition of a method call operator. */
#define END_OPERATOR                                                                                                   \
    std::vector<hilti::operator_::Operand> operands() const { return signature().args; }                               \
                                                                                                                       \
    std::string doc() const { return signature().doc; }                                                                \
                                                                                                                       \
    hilti::Type result(const node::range<hilti::Expression>& ops) const {                                              \
        return *hilti::operator_::type(signature().result, ops, ops);                                                  \
    }                                                                                                                  \
                                                                                                                       \
    bool isLhs() const { return signature().lhs; }                                                                     \
                                                                                                                       \
    void validate(const hilti::expression::ResolvedOperator& /* i */, hilti::operator_::position_t /* p */) const {}   \
                                                                                                                       \
    __END_OPERATOR_CUSTOM

/**
 * Starts definition of an operator that provides its own implementation of the
 * API's methods.
 *
 * @param ns namespace to define the operator in
 * @param op ``operator_::dnd`` for the operator
 */
#define BEGIN_OPERATOR_CUSTOM(ns, op) __BEGIN_OPERATOR_CUSTOM(ns, op, op)

/**
 * Ends definition of an operator that provides its own implementation of the
 * API's methods..
 */
#define END_OPERATOR_CUSTOM __END_OPERATOR_CUSTOM

/**
 * Starts definition of an operator that provides its own implementation of the
 * API's methods. This version allows to specify a custom class name, which
 * allows for overloading.
 *
 * @param ns namespace to define the operator in
 * @param cls name of the operator's class
 * @param op ``operator_::Kind`` for the operator
 */
#define BEGIN_OPERATOR_CUSTOM_x(ns, cls, op) __BEGIN_OPERATOR_CUSTOM(ns, op, cls)

/**
 * Ends definition of an operator that provides its own implementation of the
 * API's methods. This ends the version that specify's a custom class name.
 */
#define END_OPERATOR_CUSTOM_x __END_OPERATOR_CUSTOM


/**
 * Shortcut version for defining a straight-forward operator with 1 operand.
 */
#define STANDARD_OPERATOR_1(ns, op, result_, ty_op1, doc_)                                                             \
    BEGIN_OPERATOR(ns, op)                                                                                             \
        auto signature() const {                                                                                       \
            return hilti::operator_::Signature{.result = result_,                                                      \
                                               .args =                                                                 \
                                                   {                                                                   \
                                                       {.id = "op", .type = ty_op1},                                   \
                                                   },                                                                  \
                                               .doc = doc_};                                                           \
        }                                                                                                              \
    END_OPERATOR

/**
 * Shortcut version for defining a straight-forward operator with 1 operand.
 */
#define STANDARD_OPERATOR_1x(ns, cls, op, result_, ty_op1, doc_)                                                       \
    __BEGIN_OPERATOR_CUSTOM(ns, op, cls)                                                                               \
    auto signature() const {                                                                                           \
        return hilti::operator_::Signature{.result = result_,                                                          \
                                           .args =                                                                     \
                                               {                                                                       \
                                                   {.id = "op", .type = ty_op1},                                       \
                                               },                                                                      \
                                           .doc = doc_};                                                               \
    }                                                                                                                  \
    END_OPERATOR

/**
 * Shortcut version for defining a straight-forward operator with 2 operands.
 */
#define STANDARD_OPERATOR_2(ns, op, result_, ty_op1, ty_op2, doc_)                                                     \
    BEGIN_OPERATOR(ns, op)                                                                                             \
        auto signature() const {                                                                                       \
            return hilti::operator_::Signature{.result = result_,                                                      \
                                               .args = {{.id = "op0", .type = ty_op1}, {.id = "op1", .type = ty_op2}}, \
                                               .doc = doc_};                                                           \
        }                                                                                                              \
    END_OPERATOR

/**
 * Shortcut version for defining a straight-forward operator with 2 operands.
 */
#define STANDARD_OPERATOR_2x(ns, cls, op, result_, ty_op1, ty_op2, doc_)                                               \
    __BEGIN_OPERATOR_CUSTOM(ns, op, cls)                                                                               \
    auto signature() const {                                                                                           \
        return hilti::operator_::Signature{.result = result_,                                                          \
                                           .args = {{.id = "op0", .type = ty_op1}, {.id = "op1", .type = ty_op2}},     \
                                           .doc = doc_};                                                               \
    }                                                                                                                  \
    END_OPERATOR

/**
 * Shortcut version for defining a straight-forward LHS operator with 2 operands.
 */
#define STANDARD_OPERATOR_2x_lhs(ns, cls, op, result_, ty_op1, ty_op2, doc_)                                           \
    __BEGIN_OPERATOR_CUSTOM(ns, op, cls)                                                                               \
    auto signature() const {                                                                                           \
        return hilti::operator_::Signature{.lhs = true,                                                                \
                                           .result = result_,                                                          \
                                           .args = {{.id = "op0", .type = ty_op1}, {.id = "op1", .type = ty_op2}},     \
                                           .doc = doc_};                                                               \
    }                                                                                                                  \
    END_OPERATOR

/**
 * Shortcut version for defining a straight-forward operator with 3 operands.
 */
#define STANDARD_OPERATOR_3(ns, op, result_, ty_op1, ty_op2, ty_op3, doc_)                                             \
    BEGIN_OPERATOR(ns, op)                                                                                             \
        auto signature() const {                                                                                       \
            return hilti::operator_::Signature{.result = result_,                                                      \
                                               .args = {{.id = "op0", .type = ty_op1},                                 \
                                                        {.id = "op1", .type = ty_op2},                                 \
                                                        {.id = "op2", .type = ty_op3}},                                \
                                               .doc = doc_};                                                           \
        }                                                                                                              \
    END_OPERATOR

/**
 * Starts definition of a method call operator. This macroi is for the simple
 * case where the return type is static and no custom validation is needed.
 *
 * @param ns namespace to define the operator in
 * @param op Name for the operator (i.e., it's C++-level ID)
 */
#define BEGIN_METHOD(ns, method) __BEGIN_OPERATOR_CUSTOM(ns, MemberCall, method)

/**
 * Starts definition of a method call operator that provides its own result()
 * and validate() implementation.
 *
 * @param ns namespace to define the operator in
 * @param op Name for the operator (i.e., it's C++-level ID)
 */
#define BEGIN_METHOD_CUSTOM_RESULT(ns, method) __BEGIN_OPERATOR_CUSTOM(ns, MemberCall, method)

/** Internal helper macro. */
#define __END_METHOD                                                                                                   \
    std::vector<hilti::operator_::Operand> operands() const {                                                          \
        return {{.type = signature().self},                                                                            \
                {.type = hilti::type::Member(signature().id)},                                                         \
                {.type = hilti::type::OperandList(signature().args)}};                                                 \
    }                                                                                                                  \
                                                                                                                       \
    std::string doc() const { return signature().doc; }

/** Ends definition of a method call operator. */
#define END_METHOD                                                                                                     \
    __END_METHOD                                                                                                       \
                                                                                                                       \
    hilti::Type result(const node::range<hilti::Expression>& ops) const {                                              \
        return *hilti::operator_::type(signature().result, node::range(ops), ops);                                     \
    }                                                                                                                  \
                                                                                                                       \
    bool isLhs() const { return false; }                                                                               \
                                                                                                                       \
    void validate(const hilti::expression::ResolvedOperator& /* i */, hilti::operator_::position_t /* p */) const {}   \
                                                                                                                       \
    __END_OPERATOR_CUSTOM

/**
 * Ends definition of a method call operator that provides its own result()
 * and validate() implementation.
 */
#define END_METHOD_CUSTOM_RESULT                                                                                       \
    __END_METHOD                                                                                                       \
    __END_OPERATOR_CUSTOM

/**
 * Starts definition of a constructor-style call operator.
 *
 * @param ns namespace to define the operator in
 * @param cls name of the operator's class
 */
#define BEGIN_CTOR(ns, cls) __BEGIN_OPERATOR_CUSTOM(ns, Call, cls)

#define END_CTOR                                                                                                       \
    std::vector<hilti::operator_::Operand> operands() const {                                                          \
        return {{.type = hilti::type::Type_(ctorType())}, {.type = hilti::type::OperandList(signature().args)}};       \
    }                                                                                                                  \
                                                                                                                       \
    std::string doc() const { return signature().doc; }                                                                \
                                                                                                                       \
    hilti::Type result(const node::range<hilti::Expression>& ops) const {                                              \
        if ( ops.size() )                                                                                              \
            return ops[0].type().as<hilti::type::Type_>().typeValue();                                                 \
                                                                                                                       \
        return ctorType();                                                                                             \
    }                                                                                                                  \
                                                                                                                       \
    bool isLhs() const { return false; }                                                                               \
                                                                                                                       \
    void validate(const hilti::expression::ResolvedOperator& /* i */, hilti::operator_::position_t /* p */) const {}   \
                                                                                                                       \
    __END_OPERATOR_CUSTOM

/**
 * No-op to have the auto-generated code pick up on an operator that's
 * fully defined separately.
 */
#define OPERATOR_DECLARE_ONLY(ns, cls)
