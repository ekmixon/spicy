// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/types/vector.h>
#include <hilti/base/uniquer.h>
#include <hilti/base/util.h>

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
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), hilti::type::pruneWalk(std::move(type)), hilti::type::auto_,
                         hilti::node::none, hilti::type::auto_, node::none, repeat, std::move(attrs), std::move(cond),
                         args, sinks, hooks),
                   std::move(m)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(9),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, Ctor ctor, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          Meta m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), hilti::node::none, hilti::type::auto_, hilti::node::none,
                         hilti::type::auto_, ctor, repeat, std::move(attrs), std::move(cond), args, sinks, hooks),
                   std::move(m)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(9),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, Item item, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          const Meta& m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), hilti::node::none, hilti::type::auto_, hilti::node::none,
                         hilti::type::auto_, std::move(item), repeat, std::move(attrs), std::move(cond), args, sinks,
                         hooks),
                   m),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(9),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, NodeRef type, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          const Meta& m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), node::none, hilti::type::auto_, hilti::node::none,
                         hilti::type::auto_, node::none, repeat, std::move(attrs), std::move(cond), args, sinks, hooks),
                   std::move(m)),
          _type(std::move(type)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(9),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {
        (*_type)->isA<hilti::declaration::Type>();
    }

    Field() = delete;
    Field(const Field& other) = default;
    Field(Field&& other) = default;
    ~Field() = default;

    const auto& id() const { return childs()[0].as<ID>(); }
    auto index() const { return _index; }
    auto ctor() const { return childs()[5].tryAs<Ctor>(); }
    auto item() const { return childs()[5].tryAs<Item>(); }

    auto repeatCount() const { return childs()[6].tryAs<Expression>(); }
    auto attributes() const { return childs()[7].tryAs<AttributeSet>(); }
    auto condition() const { return childs()[8].tryAs<Expression>(); }
    auto arguments() const { return childs<Expression>(_args_start, _args_end); }
    auto sinks() const { return childs<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return childs<Hook>(_hooks_start, _hooks_end); }
    Engine engine() const { return _engine; }

    bool isContainer() const { return repeatCount().has_value(); }
    bool isForwarding() const { return _is_forwarding; }
    bool isTransient() const { return _is_transient; }
    bool emitHook() const { return ! isTransient() || hooks().size(); }

    const Type& originalType() const {
        if ( _type )
            return (*_type)->as<hilti::declaration::Type>().type();

        if ( auto t = childs()[1].tryAs<Type>() )
            return *t;

        if ( auto c = ctor() )
            return c->type();

        if ( auto i = item() )
            return i->itemType();

        hilti::util::cannot_be_reached();
    }

    const Type& parseType() const { return childs()[2].as<Type>(); }
    NodeRef parseTypeRef() const { return NodeRef(childs()[2]); }
    const Type& itemType() const { return childs()[4].as<Type>(); }

    const Type& ddType() const {
        if ( auto x = childs()[3].tryAs<hilti::declaration::Expression>() )
            return x->expression().type();
        else
            return hilti::type::auto_;
    }

    NodeRef ddRef() const {
        if ( childs()[3].isA<Declaration>() )
            return NodeRef(childs()[3]);
        else
            return {};
    }

    auto itemRef() { return NodeRef(childs()[5]); }

    // Get the `&convert` expression, if any.
    std::optional<std::pair<const Expression, std::optional<const Type>>> convertExpression() const;

    void setForwarding(bool is_forwarding) { _is_forwarding = is_forwarding; }
    void setDDType(Type t) { childs()[3] = hilti::expression::Keyword::createDollarDollarDeclaration(std::move(t)); }
    void setIndex(uint64_t index) { _index = index; }
    void setItemType(Type t) { childs()[4] = hilti::type::pruneWalk(std::move(t)); }
    void setParseType(Type t) { childs()[2] = hilti::type::pruneWalk(std::move(t)); }

    bool operator==(const Field& other) const {
        return _engine == other._engine && id() == other.id() && originalType() == other.originalType() &&
               itemType() == other.itemType() && parseType() == other.parseType() &&
               attributes() == other.attributes() && arguments() == other.arguments() && sinks() == other.sinks() &&
               condition() == other.condition() && hooks() == other.hooks();
    }

    Field& operator=(const Field& other) = default;
    Field& operator=(Field&& other) = default;

    // Unit item interface
    bool isResolved() const { return _type || item() || type::isResolved(itemType()); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const {
        return node::Properties{{"engine", to_string(_engine)},
                                {"transient", _is_transient},
                                {"forwarding", _is_forwarding}};
    }

private:
    std::optional<NodeRef> _type;
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
