// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/ast/types/tuple.h"

#include <algorithm>
#include <exception>
#include <functional>

using namespace hilti;

std::optional<std::pair<int, const type::tuple::Element*>> type::Tuple::elementByID(const ID& id) const {
    int i = 0;
    for ( const auto& e : elements() ) {
        if ( e.id() == id )
            return std::make_optional(std::make_pair(i, &e));

        i++;
    }

    return {};
}
