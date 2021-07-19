// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/types/vector.h>
#include <hilti/base/uniquer.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/** AST node for a unit field. */
class Field : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Field(const std::optional<ID>& id, Type type, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          Meta m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), std::move(type), hilti::type::auto_, hilti::type::auto_,
                         node::none, repeat, std::move(attrs), std::move(cond), args, sinks, hooks),
                   std::move(m)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(8),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, Ctor ctor, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          Meta m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), ctor.type(), hilti::type::auto_, hilti::type::auto_, ctor,
                         repeat, std::move(attrs), std::move(cond), args, sinks, hooks),
                   std::move(m)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(8),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, Item item, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          const Meta& m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), item.itemType(), hilti::type::auto_, hilti::type::auto_,
                         item, repeat, std::move(attrs), std::move(cond), args, sinks, hooks),
                   m),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(8),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field() = delete;
    Field(const Field& other) = default;
    Field(Field&& other) = default;
    ~Field() = default;

    const auto& id() const { return childs()[0].as<ID>(); }
    auto index() const { return _index; }
    auto ctor() const { return childs()[4].tryReferenceAs<Ctor>(); }
    auto item() const { return childs()[4].tryReferenceAs<Item>(); }

    auto repeatCount() const { return childs()[5].tryReferenceAs<Expression>(); }
    auto attributes() const { return childs()[6].tryReferenceAs<AttributeSet>(); }
    auto condition() const { return childs()[7].tryReferenceAs<Expression>(); }
    auto arguments() const { return childs<Expression>(_args_start, _args_end); }
    auto sinks() const { return childs<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return childs<Hook>(_hooks_start, _hooks_end); }
    Engine engine() const { return _engine; }

    bool isContainer() const { return repeatCount().has_value(); }
    bool isForwarding() const { return _is_forwarding; }
    bool isTransient() const { return _is_transient; }
    bool emitHook() const { return ! isTransient() || hooks().size(); }

    const Type& originalType() const { return childs()[1].as<Type>(); }
    const Type& itemType() const { return childs()[2].as<Type>(); }
    const Type& parseType() const { return childs()[3].as<Type>(); }

    // TODO: Can we get rid of these?
    Node& originalTypeNode() { return childs()[1]; }
    Node& ctorNode() { return childs()[4]; }
    Node& itemNode() { return childs()[4]; }
    Node& attributesNode() { return childs()[6]; }

    // Get the `&convert` expression, if any.
    hilti::optional_ref<const Expression> convertExpression() const {
        if ( auto convert = AttributeSet::find(attributes(), "&convert") )
            return (*convert->valueAsExpression()).get();
        else
            return {};
    }

    void setForwarding(bool is_forwarding) { _is_forwarding = is_forwarding; } // TODO: Do we still need this?
    void setIndex(uint64_t index) { _index = index; }
    void setItemType(Type t) { childs()[2] = std::move(t); }
    void setParseType(Type t) { childs()[3] = std::move(t); }

    bool operator==(const Field& other) const {
        return _engine == other._engine && id() == other.id() && originalType() == other.originalType() &&
               itemType() == other.itemType() && parseType() == other.parseType() &&
               attributes() == other.attributes() && arguments() == other.arguments() && sinks() == other.sinks() &&
               condition() == other.condition() && hooks() == other.hooks();
    }

    Field& operator=(const Field& other) = default;
    Field& operator=(Field&& other) = default;

    // Unit item interface
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const {
        return node::Properties{{"engine", to_string(_engine)},
                                {"transient", _is_transient},
                                {"forwarding", _is_forwarding}};
    }

private:
    std::optional<uint64_t> _index;
    bool _is_forwarding;
    bool _is_transient;
    Engine _engine;
    int _args_start;
    int _args_end;
    int _sinks_start;
    int _sinks_end;
    int _hooks_start;
    int _hooks_end;

    static inline hilti::util::Uniquer<ID> _uniquer;
};

} // namespace spicy::type::unit::item
