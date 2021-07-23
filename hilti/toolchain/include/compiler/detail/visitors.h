// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>

namespace hilti {

class Unit;

namespace printer {
class Stream;
} // namespace printer

namespace detail {

/**Performs imports for an AST. */
std::set<context::ModuleIndex> importModules(const Node& root, Unit* unit);

/**
 * Prints an AST as HILTI source code. This consults any installed plugin
 * `print_ast` hooks.
 */
void printAST(const Node& root, std::ostream& out, bool compact = false);

/**
 * Prints an AST as HILTI source code. This consults any installed plugin
 * `print_ast` hooks.
 */
void printAST(const Node& root, printer::Stream& stream); // NOLINT

/** Returns a string with the prototype for an operator for display. */
std::string renderOperatorPrototype(const expression::UnresolvedOperator& o);

/** Returns a string with the prototype for an operator for display. */
std::string renderOperatorPrototype(const expression::ResolvedOperator& o);

/** Returns a string with an instantiated  operator for display. */
std::string renderOperatorInstance(const expression::UnresolvedOperator& o);

/** Returns a string with an instantiated  operator for display. */
std::string renderOperatorInstance(const expression::ResolvedOperator& o);

/** Prints a debug dump of a node, including its childrens. */
void renderNode(const Node& n, std::ostream& out, bool include_scopes = false);
void renderNode(const Node& n, logging::DebugStream stream, bool include_scopes = false);

namespace ast {

void clearErrors(Node* root);
void buildScopes(Node* root, Unit* unit);
bool normalize(Node* root, Unit* unit);
bool coerce(Node* root, Unit* unit);
bool resolve(Node* root, Unit* unit);
void validate(Node* root);
} // namespace ast

#if 0
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolveIDs(Node* root, Unit* unit);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolveTypes(Node* root, Unit* unit);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolveOperators(Node* root, Unit* unit);
#endif

} // namespace detail
} // namespace hilti
