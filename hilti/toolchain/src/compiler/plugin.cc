// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/autogen/config.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace hilti::detail;

PluginRegistry::PluginRegistry() = default; // Neded here to allow PluginRegistry to be forward declared.

Result<Plugin> PluginRegistry::pluginForExtension(hilti::rt::filesystem::path ext) const {
    auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.extension == ext; });
    if ( p != _plugins.end() )
        return *p;

    return result::Error(util::fmt("no plugin registered for extension %s", ext));
}

const Plugin& PluginRegistry::hiltiPlugin() const {
    static const Plugin* hilti_plugin = nullptr;

    if ( ! hilti_plugin ) {
        auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.component == "HILTI"; });
        if ( p == _plugins.end() )
            logger().fatalError("cannot retrieve HILTI plugin");

        hilti_plugin = &*p;
    }

    return *hilti_plugin;
}

PluginRegistry& plugin::registry() {
    static PluginRegistry singleton;
    return singleton;
}

void PluginRegistry::register_(const Plugin& p) {
    _plugins.push_back(p);
    std::sort(_plugins.begin(), _plugins.end(), [](const auto& x, const auto& y) { return x.order < y.order; });
}

// Always-on default plugin with HILTI functionality.
static Plugin hilti_plugin() {
    return Plugin{
        .component = "HILTI",
        .extension = ".hlt",
        .cxx_includes = {"hilti/rt/libhilti.h"},
        .order = 100,

        .library_paths =
            [](const std::shared_ptr<hilti::Context>& ctx) { return hilti::configuration().hilti_library_paths; },

        .parse = [](std::istream& in, const hilti::rt::filesystem::path& path) { return parseSource(in, path); },

        .coerce_ctor = [](Ctor c, const Type& dst,
                          bitmask<CoercionStyle> style) { return detail::coerceCtor(std::move(c), dst, style); },

        .coerce_type = [](Type t, const Type& dst,
                          bitmask<CoercionStyle> style) { return detail::coerceType(std::move(t), dst, style); },

        .ast_build_scopes = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                               Unit* u) { ast::buildScopes(m, u); },

        .ast_normalize = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                            Unit* u) { return ast::normalize(m, u); },

        .ast_resolve = [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) { return ast::resolve(m, u); },

        .ast_coerce = [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) { return ast::coerce(m, u); },

        .ast_validate = [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) { ast::validate(m); },

        .transform = {},
    };
}

static plugin::Register _(hilti_plugin());
