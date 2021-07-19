// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "spicy/ast/types/unit-items/field.h"

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/computed.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/vector.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/bitfield.h>

using namespace spicy;
using namespace spicy::detail;

namespace {} // namespace
