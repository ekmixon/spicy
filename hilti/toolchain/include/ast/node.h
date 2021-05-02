// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
#pragma once

#include <cinttypes>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace std {
// TODO: Do this differently.
template<typename T>
bool operator==(const vector<std::reference_wrapper<T>>& a, const vector<std::reference_wrapper<T>>& b) {
    if ( &a == &b )
        return true;

    if ( a.size() != b.size() )
        return false;

    auto i = a.begin();
    auto j = b.begin();

    while ( i != a.end() ) {
        if ( (*i++).get() != (*j++).get() )
            return false;
    }

    return true;
}

} // namespace std


namespace hilti {
namespace trait {
class isNode {};
} // namespace trait
} // namespace hilti

#include <hilti/ast/meta.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/scope.h>
#include <hilti/base/type_erase.h>
#include <hilti/base/util.h>

namespace hilti {

class Node;
class NodeRef;

namespace node {
namespace detail {

/** Value of a node property, stored as part of `Properties`. */
using PropertyValue = std::variant<bool, const char*, double, int, int64_t, unsigned int, uint64_t, std::string>;

/** Renders a property value into a string for display. */
inline std::string to_string(PropertyValue v) {
    struct Visitor {
        auto operator()(bool s) { return std::string(s ? "true" : "false"); }
        auto operator()(const char* s) { return util::escapeUTF8(s); }
        auto operator()(double d) { return util::fmt("%.6f", d); }
        auto operator()(int i) { return util::fmt("%d", i); }
        auto operator()(int64_t i) { return util::fmt("%" PRId64, i); }
        auto operator()(std::string s) { return util::escapeUTF8(s); }
        auto operator()(unsigned int u) { return util::fmt("%u", u); }
        auto operator()(uint64_t u) { return util::fmt("%" PRIu64, u); }
    };

    return std::visit(Visitor(), v);
};

} // namespace detail

/** Importance of reporting an error, relative to others. */
enum class ErrorPriority {
    High = 3,   /**< High priority error that will always be reported. */
    Normal = 2, /**< Normal priority error that will be reported if there are no higher priority ones. */
    Low = 1,    /**< Low priority error that will be reported if there are no higher priority ones. */
    NoError = 0 /**< Place-holder for comparision if no error was encountered */
};

inline bool operator<(ErrorPriority x, ErrorPriority y) {
    return static_cast<std::underlying_type_t<ErrorPriority>>(x) <
           static_cast<std::underlying_type_t<ErrorPriority>>(y);
}

/** Error information associated with nodes. */
struct Error {
    std::string message;                            /**< main error message to report  */
    Location location;                              /**< location associated with the error */
    std::vector<std::string> context;               /**< additional lines to print along with error as context */
    ErrorPriority priority = ErrorPriority::Normal; /**< priortity of error */

    // Comparision considers message & location, so that we can unique based
    // on those two.
    bool operator<(const Error& other) const {
        return std::tie(message, location) < std::tie(other.message, other.location);
    }
};

// Adapted from https://www.artificialworlds.net/blog/2017/05/12/c-iterator-wrapperadaptor-example/
template<typename T>
class const_range_iterator {
private:
    using base = std::vector<Node>::const_iterator;
    base _wrapped;

    const T& value() const { return (*_wrapped).template as<std::remove_const_t<T>>(); }

public:
    // Previously provided by std::iterator
    using value_type = base::value_type;
    using difference_type = base::difference_type;
    using pointer = base::pointer;
    using reference = base::reference;
    using iterator_category = base::iterator_category;

    explicit const_range_iterator(base i) : _wrapped(i) {}
    const_range_iterator() {}
    const T& operator*() const { return value(); }
    const T& operator->() const { return value(); }
    bool operator==(const const_range_iterator& other) const { return _wrapped == other._wrapped; }
    bool operator!=(const const_range_iterator& other) const { return ! (*this == other); }
    const_range_iterator operator++(int) {
        auto x = const_range_iterator(_wrapped);
        ++_wrapped;
        return x;
    }
    const_range_iterator& operator++() {
        ++_wrapped;
        return *this;
    }

    const_range_iterator& operator+=(difference_type i) {
        _wrapped += i;
        return *this;
    }

    const_range_iterator& operator-=(difference_type i) {
        _wrapped -= i;
        return *this;
    }

    const_range_iterator operator+(difference_type i) const { return const_range_iterator(_wrapped + i); }
    const_range_iterator operator-(difference_type i) const { return const_range_iterator(_wrapped - i); }

    auto operator-(const const_range_iterator& other) const { return _wrapped - other._wrapped; }

    auto node_iter() const { return _wrapped; }
};

template<typename T>
class range {
public:
    using iterator = const_range_iterator<T>;
    using const_iterator = const_range_iterator<T>;

    range(std::vector<Node>::const_iterator begin, std::vector<Node>::const_iterator end) : _begin(begin), _end(end) {}
    // explicit range(const std::vector<Node>& nodes) : range(nodes.begin(), nodes.end()) {} // TODO: need?
    explicit range() {}

    template<typename Dummy = void, typename Dummy2 = std::enable_if_t<! std::is_same<T, Node>::value, Dummy>>
    explicit range(const std::vector<Node>& nodes) : range(nodes.begin(), nodes.end()) {}

    auto begin() const { return _begin; }
    auto end() const { return _end; }
    auto size() const { return _end - _begin; }
    const T& front() const { return *_begin; }

    bool empty() const { return _begin == _end; }

    template<typename U>
    std::vector<U> copy() const {
        std::vector<U> x;
        for ( auto i = _begin; i != _end; i++ )
            x.push_back(i.node_iter()->template as<U>());

        return x;
    }

    const T& operator[](size_t i) const { return *(_begin + i); }

    bool operator==(const range& other) const {
        if ( this == &other )
            return true;

        if ( size() != other.size() )
            return false;

        auto x = _begin;
        auto y = other._begin;
        while ( x != _end ) {
            if ( ! (*x++ == *y++) )
                return false;
        }

        return true;
    }

private:
    /*
     * std::vector<Node> _convert(std::vector<T> x) {
     *     std::vector<Node> n;
     *     for ( auto i : x )
     *         n.push_back(std::move(i));
     *
     *     return n;
     * }
     */
    const_range_iterator<T> _begin;
    const_range_iterator<T> _end;
};

template<typename T>
class const_set_iterator {
private:
    using base = typename std::vector<std::reference_wrapper<const T>>::const_iterator;
    base _wrapped;

    const T& value() const { return ((*_wrapped).get()); }

public:
    // Previously provided by std::iterator
    using value_type = T;
    using difference_type = typename base::difference_type;
    using pointer = typename base::pointer;
    using reference = typename base::reference;
    using iterator_category = typename base::iterator_category;

    explicit const_set_iterator(base i) : _wrapped(i) {}
    const T& operator*() const { return value(); }
    const T& operator->() const { return value(); }
    bool operator==(const const_set_iterator& other) const { return _wrapped == other._wrapped; }
    bool operator!=(const const_set_iterator& other) const { return ! (*this == other); }
    const_set_iterator operator++(int) {
        auto x = const_set_iterator(_wrapped);
        ++_wrapped;
        return x;
    }
    const_set_iterator& operator++() {
        ++_wrapped;
        return *this;
    }

    const_set_iterator& operator+=(difference_type i) {
        _wrapped += i;
        return *this;
    }

    const_set_iterator& operator-=(difference_type i) {
        _wrapped -= i;
        return *this;
    }

    const_set_iterator operator+(difference_type i) const { return _wrapped + i; }
    const_set_iterator operator-(difference_type i) const { return _wrapped - i; }

    auto operator-(const const_set_iterator& other) const { return _wrapped - other._wrapped; }

    auto node_iter() const { return _wrapped; }
};

template<typename T>
class set {
public:
    using iterator = const_set_iterator<T>;
    using const_iterator = const_set_iterator<T>;

    set() {}
    auto begin() const { return const_iterator(_set.begin()); }
    auto end() const { return const_iterator(_set.end()); }
    auto size() const { return _set.size(); }
    bool empty() const { return _set.empty(); }

    void push_back(const T& x) { _set.push_back(x); }

    const T& operator[](size_t i) const { return _set[i].get(); }

    bool operator==(const set& other) const {
        if ( this == &other )
            return true;

        if ( size() != other.size() )
            return false;

        auto x = begin();
        auto y = other.begin();
        while ( x != end() ) {
            if ( ! (*x++ == *y++) )
                return false;
        }

        return true;
    }

private:
    std::vector<std::reference_wrapper<const T>> _set;
};

template<typename A, typename B>
std::vector<std::pair<std::reference_wrapper<A>, std::reference_wrapper<B>>> zip2(const set<A>& lhs,
                                                                                  const set<B>& rhs) {
    std::vector<std::pair<std::reference_wrapper<A>, std::reference_wrapper<B>>> result;
    for ( std::pair<typename set<A>::const_iterator, typename set<B>::const_iterator> iter =
              std::pair<typename set<A>::const_iterator, typename set<B>::const_iterator>(lhs.begin(), rhs.begin());
          iter.first != lhs.end() and iter.second != rhs.end(); ++iter.first, ++iter.second )
        result.emplace_back(*iter.first, *iter.second);
    return result;
}

template<typename A, typename B>
std::vector<std::pair<std::reference_wrapper<A>, std::reference_wrapper<B>>> zip2(const range<A>& lhs,
                                                                                  const range<B>& rhs) {
    std::vector<std::pair<std::reference_wrapper<A>, std::reference_wrapper<B>>> result;
    for ( std::pair<typename range<A>::const_iterator, typename range<B>::const_iterator> iter =
              std::pair<typename range<A>::const_iterator, typename range<B>::const_iterator>(lhs.begin(), rhs.begin());
          iter.first != lhs.end() and iter.second != rhs.end(); ++iter.first, ++iter.second )
        result.emplace_back(*iter.first, *iter.second);
    return result;
}

/** Filters a vector through a boolean predicate. */
template<typename X, typename F>
auto filter(const node::range<X>& x, F f) {
    node::set<X> y;
    for ( const auto& i : x )
        if ( f(i) )
            y.push_back(i);
    return y;
}

/** Filters a vector through a boolean predicate. */
template<typename X, typename F>
auto filter(const node::set<X>& x, F f) {
    node::set<X> y;
    for ( const auto& i : x )
        if ( f(i) )
            y.push_back(i);
    return y;
}

/**
 * Properties associated with an AST node. A property is a key/value pair
 * recording node-specific, atomic information that's not represented by
 * further child nodes.
 */
using Properties = std::map<std::string, node::detail::PropertyValue>;

namespace detail {
#include <hilti/autogen/__node.h>

} // namespace detail
} // namespace node

/**
 * AST node. This is a type-erased class that wraps all AST nodes.
 *
 * @note Do not derive from this class. Derive from `NodeBase` instead and
 * then implement the `Node` interface.
 */
class Node final : public node::detail::Node {
public:
    /** Constructs a node from an instance of a class implementing the `Node` interface. */
    template<typename T, typename std::enable_if_t<std::is_base_of<trait::isNode, T>::value>* = nullptr>
    Node(T t) : node::detail::Node(std::move(t)) {}

    Node(const Node& other) : node::detail::Node::Node(other), _scope(other._scope), _alias(other._alias) {}
    Node(Node&& other) noexcept
        : node::detail::Node::Node(std::move(other)),
          _control_ptr(std::move(other._control_ptr)),
          _scope(std::move(other._scope)),
          _alias(other._alias) {
        if ( _control_ptr )
            _control_ptr->_node = this;
    }

    Node() = delete;

    // explicit Node(IntrusivePtr<hilti::node::detail::Concept> data) : node::detail::Node(std::move(data)) {}

    ~Node() final {
        if ( _control_ptr )
            _control_ptr->_node = nullptr;
    }

    /**
     * Returns the node's unique control ID if there's at least `NodeRef` has
     * been created that refers to it. If there's no such NodeRef, returns
     * zero.
     *
     * @note This is primarily for internal usage.
     */
    uint64_t rid() const { return _control_ptr ? _control_ptr->_rid : 0; }

    /**
     * Returns a string representation of `rid()`.
     *
     * @note This is primarily for internal usage.
     */
    std::string renderedRid() const { return rid() ? util::fmt("%%%" PRIu64, rid()) : "%???"; };

    /**
     * Returns the scope associated with the node. All nodes have a scope
     * used for ID resolution. Initially, a new node receive its own, empty
     * scope. However, scopes can be shared across nodes through
     * `setScope()`.
     */
    IntrusivePtr<Scope> scope() const {
        if ( ! _scope )
            _scope = make_intrusive<Scope>();

        return _scope;
    }

    /**
     * Resets the node's scope to point to another one. Nodes
     */
    void setScope(IntrusivePtr<Scope> new_scope) { _scope = std::move(new_scope); }

    /** Clears out the current scope. */
    void clearScope() {
        if ( _scope )
            _scope->clear();
    }

    /** Returns any error messages associated with the node. */
    std::vector<node::Error> errors() const {
        if ( _errors )
            return *_errors;
        else
            return {};
    }

    /** Returns true if there are any errors associated with the node. */
    bool hasErrors() const { return _errors && _errors->size(); }

    /** Clears any error message associated with the node. */
    void clearErrors() {
        if ( _errors )
            _errors.reset();
    }

    /**
     * Associate an error message with the node. The error's location will be
     * that of the current node, and it will have normal priority.
     *
     * @param msg error message to report
     * @param context further lines of context to show along with error
     *
     */
    void addError(std::string msg, std::vector<std::string> context = {}) {
        addError(std::move(msg), location(), std::move(context));
    }

    /**
     * Associate an error message with the node. The error's location will be
     * that of the current node.
     *
     * @param msg error message to report
     * @param priority importance of showing the error
     * @param context further lines of context to show along with error
     *
     */
    void addError(std::string msg, node::ErrorPriority priority, std::vector<std::string> context = {}) {
        addError(std::move(msg), location(), priority, std::move(context));
    }

    /**
     * Associate an error message with the node. The error will have normal
     * priority.
     *
     * @param msg error message to report
     * @param l custom location to associate with the error
     * @param context further lines of context to show along with error
     */
    void addError(std::string msg, Location l, std::vector<std::string> context = {}) {
        addError(std::move(msg), location(), node::ErrorPriority::Normal, std::move(context));
    }

    /**
     * Associate an error message with the node.
     *
     * @param msg error message to report
     * @param l custom location to associate with the error
     * @param priority importance of showing the error
     * @param context further lines of context to show along with error
     */
    void addError(std::string msg, Location l, node::ErrorPriority priority, std::vector<std::string> context = {}) {
        node::Error error;
        error.message = std::move(msg);
        error.location = std::move(l);
        error.context = std::move(context);
        error.priority = priority;

        if ( ! _errors )
            _errors = std::make_unique<std::vector<node::Error>>();

        _errors->push_back(std::move(error));
    }

    /**
     * Returns an internal string representation of the node and all its
     * children.
     *
     * @param include_location if true, include source code locations into
     * the output
     */
    std::string render(bool include_location = true) const;

    bool isAlias() const { return _alias; }
    void setAlias() { _alias = true; }

    /**
     * Returns a HILTI source code representation of the node and all its
     * children. If the node is not the root of an AST, it's not guaranteed
     * that the result will form valid HILTI source code (but it can still be
     * used, e.g., in error messages).
     *
     * @param compact create a one-line representation
     *
     */
    void print(std::ostream& out, bool compact = false) const;

    /** Convenience method to return the meta data's location information. */
    const Location& location() const { return meta().location(); }

    /** Aborts execution if node is not of a given type `T`. */
    template<typename T>
    void assertIsA() {
        if ( ! isA<T>() ) {
            std::cerr << "Assertion failure: Node expected to be a " << typeid(T).name() << " but is a "
                      << typeid_().name() << std::endl;
            util::abort_with_backtrace();
        }
    }

    /** Renders the node as HILTI source code. */
    operator std::string() const {
        std::stringstream buf;
        print(buf, true);
        return buf.str();
    }

    /**
     * Replaces the node with another one. Existing `NodeRef` pointing to
     * this node will remain valid and reflect the new value.
     */
    Node& operator=(const Node& n) {
        _scope = n._scope;
        _alias = n._alias;
        node::detail::ErasedBase::operator=(n);
        return *this;
    }

    /**
     * Replaces the node with another one. Existing `NodeRef` pointing to
     * this node will remain valid and reflect the new value.
     */
    Node& operator=(Node&& n) noexcept {
        _scope = std::move(n._scope);
        _alias = n._alias;
        node::detail::ErasedBase::operator=(std::move(n));
        return *this;
    }

    /**
     * Replaces the node with an instance of a class implementing the `Node`
     * interface. Existing `NodeRef` pointing to this node will remain valid
     * and reflect the new value.
     */
    template<typename T>
    Node& operator=(const T& t) {
        node::detail::ErasedBase::operator=(to_node(t));
        return *this;
    }

private:
    friend class NodeRef;

    // Returns (and potentially) created the control block for this node that
    // NodeRef uses to maintain links to it.
    IntrusivePtr<node_ref::detail::Control> _control() const {
        if ( ! _control_ptr )
            _control_ptr = make_intrusive<node_ref::detail::Control>(this);

        return _control_ptr;
    }

    mutable IntrusivePtr<node_ref::detail::Control> _control_ptr = nullptr;
    mutable IntrusivePtr<Scope> _scope = nullptr;
    std::unique_ptr<std::vector<node::Error>> _errors = nullptr;
    bool _alias = false;
};

/**
 * Common base class for classes implementing the `Node` interface. The base
 * implements a number of the interface methods with standard versions shared
 * across all nodes.
 */
class NodeBase : public trait::isNode {
public:
    /**
     * Constructor.
     *
     * @param meta meta information to associate with the node
     */
    NodeBase(Meta meta) : _meta(std::move(meta)) {}

    /**
     * Constructor registering child nodes.
     *
     * @param childs children of this node
     * @param meta meta information to associate with the node
     */
    NodeBase(std::vector<Node> childs, Meta meta) : _meta(std::move(meta)) {
        for ( auto& c : childs )
            addChild(std::move(c));
    }

    NodeBase() = default;

    /**
     * Returns a child.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param i index of the child, in the order they were passed into the constructor and/or added
     * @return child casted to type `T`
     */
    template<typename T>
    const T& child(int i) const {
        return _childs[i].as<T>();
    }

    /**
     * Aborts execution if a given child is not an expected type `T`.
     *
     * @tparam T type that the child node is assumed to have
     * @param i index of the child, in the order they were passed into the constructor and/or added
     */
    template<typename T>
    void assertChildIsA(int i) {
        _childs[i].template assertIsA<T>();
    }

    /**
     * Returns a subrange of children. The indices correspond to the order
     * children were passed into the constructor and/or added.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param begin index of first child to include; a negative index counts Python-style from end of list
     * @param end index of one beyond last child to include; a negative index counts Python-style from end of list
     * @return childs from `start` to `end`
     */
    template<typename T>
    auto childs(int begin, int end) const {
        auto end_ = (end < 0) ? _childs.end() : _childs.begin() + end;
        return node::range<T>(_childs.begin() + begin, end_);
    }

    auto childRefs(int begin, int end) {
        auto end_ = (end < 0) ? _childs.end() : _childs.begin() + end;
        std::vector<NodeRef> refs;

        for ( auto c = _childs.begin(); c != end_; c = std::next(c) )
            refs.push_back(NodeRef(*c));

        return refs;
    }

    /**
     * Returns a subset of children by type.
     *
     * @tparam T type of children to return
     * @return all childs that have type `T`
     */
    template<typename T>
    auto childsOfType() const {
        typename node::set<T> n;
        for ( auto c = _childs.begin(); c != _childs.end(); c = std::next(c) ) {
            if ( auto t = c->tryAs<T>() )
                n.push_back(*t);
        }

        return n;
    }

    /**
     * Returns a subset of children `Node` references, selected by type.
     *
     * @tparam T type of children to return
     * @return all childs that have type `T`
     */
    template<typename T>
    auto nodesOfType() const {
        typename node::set<Node> n;
        for ( auto c = _childs.begin(); c != _childs.end(); c = std::next(c) ) {
            if ( c->isA<T>() )
                n.push_back(*c);
        }

        return n;
    }

    template<typename T>
    auto refsOfType() const {
        typename std::vector<NodeRef> n;
        for ( auto c = _childs.begin(); c != _childs.end(); c = std::next(c) ) {
            if ( c->isA<T>() )
                n.push_back(NodeRef(*c));
        }

        return n;
    }

    template<typename T>
    auto nodesOfType() {
        typename node::set<Node> n;
        for ( auto c = _childs.begin(); c != _childs.end(); ++c ) {
            if ( c->isA<T>() )
                n.push_back(*c);
        }

        return n;
    }

    /**
     * Adds a child node. It will be appended to the end of the current list
     * node of children.
     */
    void addChild(Node n) {
        if ( _meta.location() && ! n.location() ) {
            auto m = n.meta();
            m.setLocation(_meta.location());
            n.setMeta(std::move(m));
        }

        _childs.push_back(std::move(n));
    }

    /** Implements the `Node` interface. */
    auto& childs() const { return _childs; }
    /** Implements the `Node` interface. */
    auto& childs() { return _childs; }
    /** Implements the `Node` interface. */
    auto& meta() const { return _meta; }
    /** Implements the `Node` interface. */
    void setMeta(Meta m) { _meta = std::move(m); }
    /** Implements the `Node` interface. */
    const NodeRef& originalNode() const { return _orig; }
    /** Implements the `Node` interface. */
    void setOriginalNode(const NodeRef& n) { _orig = n; }
    /** Implements the `Node` interface. */
    void clearCache() {}

private:
    std::vector<::hilti::Node> _childs;
    Meta _meta;
    NodeRef _orig;
};

namespace node {

/** Place-holder node for an optional node that's not set. */
class None : public NodeBase, public util::type_erasure::trait::Singleton {
public:
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Wrapper around constructor so that we can make it private. Don't use
     * this, use the singleton `type::unknown` instead.
     */
    static None create() { return None(); }

private:
    None() : NodeBase(Meta()) {}
};

inline Node makeAlias(const Node& n) {
    auto x = Node(n);
    x.setAlias();
    return x;
}

/** Singleton. */
static const Node none = None::create();

} // namespace node

inline const Node& to_node(const node::None& /* n */) { return node::none; }

/**
 * No-op function implementing the `to_node` API for instances that already
 * are of type `Node`.
 */
template<typename T, IF_SAME(T, Node)> // Don't allow derived classes.
inline Node to_node(const T& n) {
    return n;
}

/** Implements the `to_node` API for optional nodes. */
template<typename T>
Node to_node(std::optional<T> t) {
    if ( t )
        return to_node(std::move(*t));

    return to_node(node::none);
}

/**
 * Creates `Node` instances for a vector of objects all implementing the
 * `Node` interface.
 */
template<typename T>
std::vector<Node> nodes(std::vector<T> t) {
    std::vector<Node> v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));
    return v;
}

/**
 * Creates `Node` instances for a list of objects all implementing the
 * `Node` interface.
 */
template<typename T>
std::vector<Node> nodes(std::list<T> t) {
    std::vector<Node> v;
    for ( const auto& i : t )
        v.emplace_back(std::move(i));
    return v;
}

/**
 * Creates `Node` instances for a set of objects all implementing the `Node`
 * interface.
 */
template<typename T>
std::vector<Node> nodes(std::set<T> t) {
    std::vector<Node> v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));
    return v;
}

template<typename T>
std::vector<Node> nodes(node::range<T> t) {
    std::vector<Node> v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));
    return v;
}

/**
 * Creates `Node` instances for a vector of pairs of objects all implementing
 * the `Node` interface. The pair will be flattened in the result.
 */
template<typename T, typename U>
std::vector<Node> nodes(std::vector<std::pair<T, U>> t) {
    std::vector<Node> v;
    v.reserve(t.size() * 2);
    for ( const auto& i : t ) {
        v.emplace_back(std::move(i.first));
        v.emplace_back(std::move(i.second));
    }
    return v;
}

/** Create a 1-element vector of nodes for an object implementing the `Node` API. */
template<typename T>
std::vector<Node> nodes(T t) {
    return {to_node(std::move(t))};
}

/**
 * Creates `Node` instances for objects all implementing the `Node`
 * interface.
 */
template<typename T, typename... Ts>
std::vector<Node> nodes(T t, Ts... ts) {
    return util::concat(std::move(nodes(t)), nodes(std::move(ts)...));
}

/**
 * Checks equality for two objects both implementing the `Node` interface.
 *
 * If the two objects have different types, this will return false. Otherwise
 * it will forward to the objects equality operator.
 */
namespace node {
template<typename T, typename Other, IF_DERIVED_FROM(T, trait::isNode), IF_DERIVED_FROM(Other, trait::isNode)>
bool isEqual(const T* this_, const Other& other) {
    if ( const auto o = other.template tryAs<T>() )
        return *this_ == *o;

    return false;
}

} // namespace node

/** Renders a node as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, const Node& n) {
    n.print(out, true);
    return out;
}

namespace node {
namespace detail {
// Backend to NodeBase::flattenedChilds.
template<typename T>
void flattenedChilds(const Node& n, std::vector<T>* dst) {
    for ( const auto& c : n.childs() ) {
        if ( auto t = c.tryAs<T>() )
            dst->push_back(*t);

        flattenedChilds(c, dst);
    }
}

} // namespace detail

/**
 * Returns a list of all childs of specific type, descending recursively
 * to find instance anywhere below this node.
 */
template<typename T>
std::vector<T> flattenedChilds(const Node& n) {
    std::vector<T> dst;
    detail::flattenedChilds<T>(n, &dst);
    return dst;
}

} // namespace node

} // namespace hilti

extern hilti::node::Properties operator+(const hilti::node::Properties& p1, const hilti::node::Properties& p2);
