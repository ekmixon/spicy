// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/compiler/plugin.h>

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

        .coerce_ctor = [](Ctor c, const Type& dst,
                          bitmask<hilti::CoercionStyle> style) { return detail::coerceCtor(std::move(c), dst, style); },

        .coerce_type = [](Type t, const Type& dst,
                          bitmask<hilti::CoercionStyle> style) { return detail::coerceType(std::move(t), dst, style); },

        .build_scopes = [](const std::shared_ptr<hilti::Context>& /* ctx */,
                           const std::vector<std::pair<ID, NodeRef>>& m, hilti::Unit* u) { buildScopes(m, u); },

        .resolve_ids = [](const std::shared_ptr<hilti::Context>& /* ctx */, Node* n,
                          hilti::Unit* u) { return resolveIDs(n, u); },

        // TODO(bbannier): The following line is inconsistently formatted
        // between clang-format-10 and clang-format-11. Remove this opt out
        // once we bump the CI formatting to llvm-11.
        // clang-format off
        .resolve_operators = [](const std::shared_ptr<hilti::Context>& /* ctx */, Node* /* n */, hilti::Unit *
                                /* u */) -> bool { return false; },
        // clang-format on

        .apply_coercions = [](const std::shared_ptr<hilti::Context>& /* ctx */, Node* n,
                              hilti::Unit* u) { return applyCoercions(n, u); },

        .validate = [](const std::shared_ptr<hilti::Context>& /* ctx */, Node* n,
                       hilti::Unit* u) { postTransformValidateAST(n, u); },

        .transform = [](std::shared_ptr<hilti::Context> ctx, Node* n, bool init, hilti::Unit* u) -> bool {
            return CodeGen(std::move(ctx)).compileModule(n, init, u);
        },

        .print_ast = [](const Node& root, hilti::printer::Stream& out) { return printAST(root, out); }};
}

static hilti::plugin::Register _(spicy_plugin());
