// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/id.h>
#include <hilti/ast/types/unknown.h>

using namespace hilti;

bool type::isResolved(const Type& t) {
    ResolvedState rstate;
    return isResolved(t, &rstate);
}

bool type::isResolved(const Type& t, ResolvedState* rstate) {
    if ( ! rstate )
        return isResolved(t);

    if ( type::isParameterized(t) ) {
        if ( rstate->find(t.identity()) != rstate->end() )
            return true;

        rstate->insert(t.identity());
    }

    return t._isResolved(rstate);
}
