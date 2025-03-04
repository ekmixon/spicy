// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/location.h>

namespace hilti {

/**
 * Meta information associated with AST nodes. The meta data can include a
 * source code location, source code comments, and an error message.
 */
class Meta {
public:
    /** List of comments. */
    using Comments = std::vector<std::string>;

    Meta(Location location, Comments comments = {}) : _comments(std::move(comments)) {
        setLocation(std::move(location));
    }

    /** Constructor that leaves location unset. */
    Meta(Comments comments = {}) : _comments(std::move(comments)) {}

    const Comments& comments() const { return _comments; }
    const Location& location() const {
        static Location null;
        return _location ? *_location : null;
    }

    void setLocation(Location l) { _location = &*_cache()->insert(std::move(l)).first; }
    void setComments(Comments c) { _comments = std::move(c); }

    /**
     * Returns true if the location does not equal a default constructed
     * instance.
     */
    explicit operator bool() const { return _location || _comments.size(); }

private:
    std::unordered_set<Location>* _cache();

    const Location* _location = nullptr;
    Comments _comments;
};

} // namespace hilti
