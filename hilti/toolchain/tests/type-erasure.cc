// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstdlib>
#include <sstream>

#include <hilti/ast/types/all.h>
#include <hilti/global.h>

using namespace hilti;

TEST_SUITE_BEGIN("type-erasure");

static auto to_string(const Type& t) {
    std::stringstream buf;
    print(buf, t, true);
    return buf.str();
}

static auto to_string(const type::function::Result& r) {
    std::stringstream buf;
    print(buf, r, true);
    return buf.str();
}

TEST_CASE("Type - copy") {
    // Shallow copy.
    Type t1 = type::Optional(type::Bool());
    Type t2 = t1;
    t1.childs()[0] = Type(type::String());

    CHECK_EQ(to_string(t1), "optional<string>");
    CHECK_EQ(to_string(t2), to_string(t1));
}

TEST_CASE("Type - alias") {
    // Shallow copy, but sets the alias flag.
    Node t1 = Type(type::Optional(type::Bool()));
    Node t2 = node::makeAlias(t1);
    t1.as<type::Optional>().childs()[0] = Type(type::String());

    CHECK_EQ(to_string(t1), "optional<string>");
    CHECK_EQ(to_string(t2), to_string(t1));
    CHECK(t2.isAlias());

    Node t3 = t2;
    CHECK_EQ(to_string(t2), to_string(t3));
    CHECK(t3.isAlias());
}

/* TODO: Enable
 * TEST_CASE("Type - clone") {
 *     // Deep copy.
 *     Type t1 = type::Optional(type::Bool());
 *     Type t2 = t1._clone();
 *     t1.childs()[0] = Type(type::String());
 *
 *     CHECK_EQ(to_string(t1), "optional<string>");
 *     CHECK_EQ(to_string(t2), "optional<bool>");
 * }
 */
TEST_CASE("function::Result - copy") {
    // Deep copy.
    auto r1 = type::function::Result(type::Bool());
    auto r2 = r1;
    r1.childs()[0] = type::String();

    CHECK_EQ(to_string(r1), "string");
    CHECK_EQ(to_string(r2), to_string(r1));
    // CHECK(! r1.isAlias());
}


TEST_SUITE_END();
