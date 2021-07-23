// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/compiler/plugin.h>
#include <hilti/compiler/printer.h>

#include <spicy/ast/aliases.h>
#include <spicy/autogen/config.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/visitors.h>
#include <spicy/global.h>

using namespace spicy;
using namespace spicy::detail;

static hilti::Plugin spicy_plugin() {
    return hilti::Plugin{
        .component = "Spicy",
        .extension = ".spicy",
        .cxx_includes = {"spicy/rt/libspicy.h"},
        .order = 2,

        .library_paths =
            [](const std::shared_ptr<hilti::Context>& /* ctx */) { return spicy::configuration().spicy_library_paths; },

        .parse = [](std::istream& in, const hilti::rt::filesystem::path& path) { return parseSource(in, path); },

        .coerce_ctor =
            [](Ctor c, const Type& dst, bitmask<hilti::CoercionStyle> style) {
                return (*hilti::plugin::registry().hiltiPlugin().coerce_ctor)(c, dst, style);
            },

        .coerce_type =
            [](Type t, const Type& dst, bitmask<hilti::CoercionStyle> style) {
                return (*hilti::plugin::registry().hiltiPlugin().coerce_type)(t, dst, style);
            },

        .ast_build_scopes = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                               hilti::Unit* u) { ast::buildScopes(ctx, m, u); },

        .ast_normalize = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                            hilti::Unit* u) { return ast::normalize(ctx, m, u); },

        .ast_resolve = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                          hilti::Unit* u) { return ast::resolve(ctx, m, u); },

        .ast_coerce = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                         hilti::Unit* u) { return (*hilti::plugin::registry().hiltiPlugin().ast_coerce)(ctx, m, u); },

        .ast_validate = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                           hilti::Unit* u) { ast::validate(ctx, m, u); },

        .ast_print = [](const Node& root, hilti::printer::Stream& out) { return ast::print(root, out); },

        .transform = [](std::shared_ptr<hilti::Context> ctx, Node* n, hilti::Unit* u) -> bool {
            return CodeGen(std::move(ctx)).compileModule(n, u);
        },
    };
}

static hilti::plugin::Register _(spicy_plugin());
