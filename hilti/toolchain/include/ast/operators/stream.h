// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expressions/id.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/stream.h>

namespace hilti {
namespace operator_ {

// stream::Iterator

STANDARD_OPERATOR_1(stream::iterator, Deref, type::UnsignedInteger(64), type::constant(type::stream::Iterator()),
                    "Returns the character the iterator is pointing to.");
STANDARD_OPERATOR_1(stream::iterator, IncrPostfix, type::stream::Iterator(), type::stream::Iterator(),
                    "Advances the iterator by one byte, returning the previous position.");
STANDARD_OPERATOR_1(stream::iterator, IncrPrefix, type::stream::Iterator(), type::stream::Iterator(),
                    "Advances the iterator by one byte, returning the new position.");

STANDARD_OPERATOR_2(
    stream::iterator, Equal, type::Bool(), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same stream value.");
STANDARD_OPERATOR_2(
    stream::iterator, Unequal, type::Bool(), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same stream value.");
STANDARD_OPERATOR_2(
    stream::iterator, Lower, type::Bool(), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same stream value.");
STANDARD_OPERATOR_2(
    stream::iterator, LowerEqual, type::Bool(), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same stream value.");
STANDARD_OPERATOR_2(
    stream::iterator, Greater, type::Bool(), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same stream value.");
STANDARD_OPERATOR_2(
    stream::iterator, GreaterEqual, type::Bool(), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same stream value.");
STANDARD_OPERATOR_2(
    stream::iterator, Difference, type::SignedInteger(64), type::constant(type::stream::Iterator()),
    type::constant(type::stream::Iterator()),
    "Returns the number of stream between the two iterators. The result will be negative if the second iterator points "
    "to a location before the first. The result is undefined if the iterators do not refer to the same stream "
    "instance.");
STANDARD_OPERATOR_2(stream::iterator, Sum, type::stream::Iterator(), type::constant(type::stream::Iterator()),
                    type::UnsignedInteger(64), "Advances the iterator by the given number of stream.")
STANDARD_OPERATOR_2(stream::iterator, SumAssign, type::stream::Iterator(), type::stream::Iterator(),
                    type::UnsignedInteger(64), "Advances the iterator by the given number of stream.")

BEGIN_METHOD(stream::iterator, Offset)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::Iterator()),
                         .result = type::UnsignedInteger(64),
                         .id = "offset",
                         .args = {},
                         .doc = R"(
Returns the offset of the byte that the iterator refers to relative to the
beginning of the underlying stream value.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::iterator, IsFrozen)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::Iterator()),
                         .result = type::Bool(),
                         .id = "is_frozen",
                         .args = {},
                         .doc = R"(
Returns whether the stream value that the iterator refers to has been frozen.
)"};
    }
END_METHOD

// stream::View

STANDARD_OPERATOR_1(stream::view, Size, type::UnsignedInteger(64), type::constant(type::stream::View()),
                    "Returns the number of stream the view contains.");
STANDARD_OPERATOR_2x(stream::view, InBytes, In, type::Bool(), type::constant(type::stream::View()),
                     type::constant(type::Bytes()),
                     "Returns true if the right-hand-side view contains the left-hand-side bytes as a subsequence.");
STANDARD_OPERATOR_2x(stream::view, InView, In, type::Bool(), type::constant(type::Bytes()),
                     type::constant(type::stream::View()),
                     "Returns true if the right-hand-side bytes contains the left-hand-side view as a subsequence.");
STANDARD_OPERATOR_2x(stream::view, EqualView, Equal, type::Bool(), type::constant(type::stream::View()),
                     type::constant(type::stream::View()), "Compares the views lexicographically.");
STANDARD_OPERATOR_2x(stream::view, EqualBytes, Equal, type::Bool(), type::constant(type::stream::View()),
                     type::constant(type::Bytes()), "Compares a stream view and a bytes intances lexicographically.");
STANDARD_OPERATOR_2x(stream::view, UnequalView, Unequal, type::Bool(), type::constant(type::stream::View()),
                     type::constant(type::stream::View()), "Compares two views lexicographically.");
STANDARD_OPERATOR_2x(stream::view, UnequalBytes, Unequal, type::Bool(), type::constant(type::stream::View()),
                     type::constant(type::Bytes()), "Compares a stream view and a bytes instance lexicographically.");

BEGIN_METHOD(stream::view, Offset)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::UnsignedInteger(64),
                         .id = "offset",
                         .args = {},
                         .doc = R"(
Returns the offset of the view's starting position within the associated stream value.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, AdvanceBy)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::View(),
                         .id = "advance",
                         .args = {{.id = "i", .type = type::stream::Iterator()}},
                         .doc = R"(
Advances the view's starting position to a given iterator *i*, returning the new
view. The iterator must be referring to the same stream values as the view, and
it must be equal or ahead of the view's starting position.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, Limit)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::View(),
                         .id = "limit",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns a new view that keeps the current start but cuts off the end *i*
characters from that beginning. The returned view will not be able to expand any
further.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, AdvanceTo)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::View(),
                         .id = "advance",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Advances the view's starting position by *i* stream, returning the new view.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, Find)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::Tuple({type::Bool(), type::stream::Iterator()}),
                         .id = "find",
                         .args = {{.id = "needle", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Searches *needle* inside the view's content. Returns a tuple of a boolean and an
iterator. If *needle* was found, the boolean will be true and the iterator will point
to its first occurance. If *needle* was not found, the boolean will be false and
the iterator will point to the last position so that everything before that is
guaranteed to not contain even a partial match of *needle* (in other words: one can
trim until that position and then restart the search from there if more data
gets appended to the underlying stream value). Note that for a simple yes/no result,
you should use the ``in`` operator instead of this method, as it's more efficient.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, At)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::Iterator(),
                         .id = "at",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns an iterator representing the offset *i* inside the view.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, StartsWith)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::Bool(),
                         .id = "starts_with",
                         .args = {{.id = "b", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Returns true if the view starts with *b*.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, SubIterators)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::View(),
                         .id = "sub",
                         .args = {{.id = "begin", .type = type::stream::Iterator()},
                                  {.id = "end", .type = type::stream::Iterator()}},
                         .doc = R"(
Returns a new view of the subsequence from *begin* up to (but not including)
*end*.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, SubIterator)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::View(),
                         .id = "sub",
                         .args = {{.id = "end", .type = type::stream::Iterator()}},
                         .doc = R"(
Returns a new view of the subsequence from the beginning of the stream up to
(but not including) *end*.
)"};
    }
END_METHOD

BEGIN_METHOD(stream::view, SubOffsets)
    auto signature() const {
        return Signature{.self = type::constant(type::stream::View()),
                         .result = type::stream::View(),
                         .id = "sub",
                         .args = {{.id = "begin", .type = type::UnsignedInteger(64)},
                                  {.id = "end", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns a new view of the subsequence from offset *begin* to (but not including)
offset *end*. The offsets are relative to the beginning of the view.
)"};
    }
END_METHOD

// Stream

STANDARD_OPERATOR_1(stream, Size, type::UnsignedInteger(64), type::constant(type::Stream()),
                    "Returns the number of stream the value contains.");
STANDARD_OPERATOR_2(stream, Unequal, type::Bool(), type::constant(type::Stream()), type::constant(type::Stream()),
                    "Compares two stream values lexicographically.");
STANDARD_OPERATOR_2x(stream, SumAssignView, SumAssign, type::Stream(), type::Stream(),
                     type::constant(type::stream::View()), "Concatenates another stream's view to the target stream.");
STANDARD_OPERATOR_2x(stream, SumAssignBytes, SumAssign, type::Stream(), type::Stream(), type::constant(type::Bytes()),
                     "Concatenates data to the stream.");

BEGIN_METHOD(stream, Freeze)
    auto signature() const {
        return Signature{.self = type::Stream(), .result = type::void_, .id = "freeze", .args = {}, .doc = R"(
Freezes the stream value. Once frozen, one cannot append any more data to a
frozen stream value (unless it gets unfrozen first). If the value is
already frozen, the operation does not change anything.
)"};
    }
END_METHOD

BEGIN_METHOD(stream, Unfreeze)
    auto signature() const {
        return Signature{.self = type::Stream(), .result = type::void_, .id = "unfreeze", .args = {}, .doc = R"(
Unfreezes the stream value. A unfrozen stream value can be further modified. If
the value is already unfrozen (which is the default), the operation does not
change anything.
)"};
    }
END_METHOD

BEGIN_METHOD(stream, IsFrozen)
    auto signature() const {
        return Signature{.self = type::constant(type::Stream()),
                         .result = type::Bool(),
                         .id = "is_frozen",
                         .args = {},
                         .doc = R"(
Returns true if the stream value has been frozen.
)"};
    }
END_METHOD

BEGIN_METHOD(stream, At)
    auto signature() const {
        return Signature{.self = type::constant(type::Stream()),
                         .result = type::stream::Iterator(),
                         .id = "at",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns an iterator representing the offset *i* inside the stream value.
)"};
    }
END_METHOD

BEGIN_METHOD(stream, Trim)
    auto signature() const {
        return Signature{.self = type::Stream(),
                         .result = type::void_,
                         .id = "trim",
                         .args = {{.id = "i", .type = type::stream::Iterator()}},
                         .doc = R"(
Trims the stream value by removing all data from its beginning up to (but not
including) the position *i*. The iterator *i* will remain valid afterwards and
will still point to the same location, which will now be the beginning of the stream's
value. All existing iterators pointing to *i* or beyond will remain valid and keep
their offsets as well. The effect of this operation is undefined if *i* does not
actually refer to a location inside the stream value. Trimming is permitted
even on frozen values.
)"};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
