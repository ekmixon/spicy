// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstring>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

class Bytes;
class RegExp;

namespace stream {
class View;
}

namespace bytes {

/** For Bytes::Strip, which side to strip from. */
enum class Side {
    Left,  /**< left side */
    Right, /**< right side */
    Both   /**< left and right sides */
};

/** For Bytes::Decode, which character set to use. */
enum class Charset { Undef, UTF8, ASCII };

class Iterator {
    using B = std::string;
    using difference_type = B::const_iterator::difference_type;

    std::weak_ptr<B*> _control;
    typename integer::safe<std::uint64_t> _index = 0;

public:
    Iterator() = default;

    Iterator(typename B::size_type index, const std::weak_ptr<B*> control)
        : _control(control), _index(std::move(index)) {}

    uint8_t operator*() const {
        if ( auto&& l = _control.lock() ) {
            auto&& data = static_cast<B&>(**l);

            if ( _index >= data.size() )
                throw IndexError(fmt("index %s out of bounds", _index));

            return data[_index];
        }

        throw InvalidIterator("bound object has expired");
    }

    template<typename T>
    auto& operator+=(const hilti::rt::integer::safe<T>& n) {
        return *this += n.Ref();
    }

    auto& operator+=(uint64_t n) {
        _index += n;
        return *this;
    }

    template<typename T>
    auto operator+(const hilti::rt::integer::safe<T>& n) const {
        return *this + n.Ref();
    }

    template<typename T>
    auto operator+(const T& n) const {
        return Iterator{_index + n, _control};
    }

    explicit operator bool() const { return static_cast<bool>(_control.lock()); }

    auto& operator++() {
        ++_index;
        return *this;
    }

    auto operator++(int) {
        auto result = *this;
        ++_index;
        return result;
    }

    friend auto operator==(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index == b._index;
    }

    friend bool operator!=(const Iterator& a, const Iterator& b) { return ! (a == b); }

    friend auto operator<(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index < b._index;
    }

    friend auto operator<=(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index <= b._index;
    }

    friend auto operator>(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index > b._index;
    }

    friend auto operator>=(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index >= b._index;
    }

    friend difference_type operator-(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot perform arithmetic with iterators into different bytes");
        return a._index - b._index;
    }
};

inline std::string to_string(const Iterator& /* i */, rt::detail::adl::tag /*unused*/) { return "<bytes iterator>"; }

inline std::ostream& operator<<(std::ostream& out, const Iterator& /* x */) {
    out << "<bytes iterator>";
    return out;
}

} // namespace bytes

/** HILTI's `Bytes` is a `std::string`-like type for wrapping raw bytes with
 * additional safety guarantees.
 *
 * If not otherwise specified, member functions have the semantics of
 * `std::string` member functions.
 */
class Bytes : protected std::string {
public:
    using Base = std::string;
    using const_iterator = bytes::Iterator;
    using Base::const_reference;
    using Base::reference;
    using Offset = uint64_t;
    using size_type = integer::safe<uint64_t>;

    using Base::Base;
    using Base::data;

    /**
     * Creates a bytes instance from a UTF8 string, transforming the contents
     * into a binary representation defined by a specified character set.
     *
     * @param s string assumed to be in UTF8 (as all runtime strings)
     * @param cs character set to use for the binary encoding
     * @return bytes instances encoding *s* in character set *cs*
     */
    Bytes(std::string s, bytes::Charset cs);

    Bytes(Base&& str) : Base(std::move(str)), _control(std::make_shared<Base*>(static_cast<Base*>(this))) {}
    Bytes(const Bytes& xs) : Base(xs), _control(std::make_shared<Base*>(static_cast<Base*>(this))) {}
    Bytes(Bytes&& xs) : Base(std::move(xs)), _control(std::make_shared<Base*>(static_cast<Base*>(this))) {}

    /** Replaces the contents of this `Bytes` with another `Bytes`.
     *
     * This function invalidates all iterators.
     *
     * @param b the `Bytes` to assign
     * @return a reference to the changed `Bytes`
     */
    Bytes& operator=(const Bytes& b) {
        invalidateIterators();
        this->Base::operator=(b);
        return *this;
    }

    /** Replaces the contents of this `Bytes` with another `Bytes`.
     *
     * This function invalidates all iterators.
     *
     * @param b the `Bytes` to assign
     * @return a reference to the changed `Bytes`
     */
    Bytes& operator=(Bytes&& b) {
        invalidateIterators();
        this->Base::operator=(std::move(b));
        return *this;
    }

    /** Appends the contents of a stream view to the data. */
    void append(const Bytes& d) { Base::append(d.str()); }

    /** Appends the contents of a stream view to the data. */
    void append(const stream::View& view);

    /** Appends a single byte the data. */
    void append(const uint8_t x) { Base::append(1, x); }

    /** Returns the bytes' data as a string instance. */
    const std::string& str() const& { return *this; }

    /** Returns an iterator representing the first byte of the instance. */
    const_iterator begin() const { return const_iterator(0u, _control); }

    /** Returns an iterator representing the end of the instance. */
    const_iterator end() const { return const_iterator(size(), _control); }

    /** Returns an iterator referring to the given offset. */
    const_iterator at(Offset o) const { return begin() + o; }

    /** Returns true if the data's size is zero. */
    bool isEmpty() const { return empty(); }

    /** Returns the size of instance in bytes. */
    size_type size() const { return static_cast<int64_t>(std::string::size()); }

    /**
     * Returns the position of the first occurence of a byte.
     *
     * @param b byte to search
     * @param n optional starting point, which must be inside the same instance
     */
    const_iterator find(value_type b, const const_iterator& n = const_iterator()) const {
        if ( auto i = Base::find(b, (n ? n - begin() : 0)); i != Base::npos )
            return begin() + i;
        else
            return end();
    }

    /**
     * Returns the position of the first occurence of a range of bytes
     *
     * @param v bytes to search
     * @param n optional starting point, which must be inside the same instance
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st bytes;
     * if no, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*.
     */
    std::tuple<bool, const_iterator> find(const Bytes& v, const const_iterator& n = const_iterator()) const;

    /**
     * Extracts a subrange of bytes.
     *
     * @param from iterator pointing to start of subrange
     * @param to iterator pointing to just beyond subrange
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(const const_iterator& from, const const_iterator& to) const {
        return {substr(from - begin(), to - from)};
    }

    /**
     * Extracts a subrange of bytes from the beginning.
     *
     * @param to iterator pointing to just beyond subrange
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(const const_iterator& to) const { return sub(begin(), to); }

    /**
     * Extracts a subrange of bytes.
     *
     * @param offset of start of subrage
     * @param offset of one byeond end of subrage
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(Offset from, Offset to) const { return {substr(from, to - from)}; }

    /**
     * Extracts a subrange of bytes from the beginning.
     *
     * @param to offset of one beyond end of subrange
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(Offset to) const { return sub(0, to); }

    /**
     * Extracts a fixed number of bytes from the data
     *
     * @tparam N number of bytes to extract
     * @param dst array to writes bytes into
     * @return new bytes instance that has the first *N* bytes removed.
     */
    template<int N>
    Bytes extract(unsigned char (&dst)[N]) const {
        if ( N > size() )
            throw InvalidArgument("insufficient data in source");

        memcpy(dst, data(), N);
        return sub(N, std::string::npos);
    }

    /**
     * Decodes the binary data into a string assuming its encoded in a
     * specified character set.
     *
     * @param cs character set to assume the binary data to be encoded in
     * @return UTF8 string
     */
    std::string decode(bytes::Charset cs) const;

    /** Returns true if the data begins with a given, other bytes instance. */
    bool startsWith(const Bytes& b) const { return hilti::rt::startsWith(*this, b); }

    /**
     * Returns an upper-case version of the instance. This internally first
     * decodes the data assuming a specified character set, then encodes it
     * back afterwards.
     *
     * @param cs character set for decoding/encoding
     * @return an upper case version of the instance
     */
    Bytes upper(bytes::Charset cs) const { return Bytes(hilti::rt::string::upper(decode(cs)), cs); }

    /** Returns an upper-case version of the instance.
     *
     * @param cs character set for decoding/encoding
     * @return a lower case version of the instance
     */
    Bytes lower(bytes::Charset cs) const { return Bytes(hilti::rt::string::lower(decode(cs)), cs); }

    /**
     * Removes leading and/or trailing sequences of all characters of a set
     * from the bytes instance.
     *
     * @param side side of bytes instance to be stripped.
     * @param set characters to remove; removes all whitespace if empty
     * @return a stripped version of the instance
     */
    Bytes strip(const Bytes& set, bytes::Side side = bytes::Side::Both) const;

    /**
     * Removes leading and/or trailing sequences of white space from the
     * bytes instance.
     *
     * @param side side of bytes instance to be stripped.
     * @return a stripped version of the instance
     */
    Bytes strip(bytes::Side side = bytes::Side::Both) const;

    /** Splits the data at sequences of whitespace, returning the parts. */
    Vector<Bytes> split() const {
        Vector<Bytes> x;
        for ( auto& v : hilti::rt::split(*this) )
            x.emplace_back(Bytes::Base(v));
        return x;
    }

    /**
     * Splits the data (only) at the first sequence of whitespace, returning
     * the two parts.
     */
    std::tuple<Bytes, Bytes> split1() const {
        auto p = hilti::rt::split1(str());
        return std::make_tuple(p.first, p.second);
    }

    /** Splits the data at occurences of a separator, returning the parts. */
    Vector<Bytes> split(const Bytes& sep) const {
        Vector<Bytes> x;
        for ( auto& v : hilti::rt::split(*this, sep) )
            x.push_back(Bytes::Base(v));
        return x;
    }

    /**
     * Splits the data (only) at the first occurance of a separator,
     * returning the two parts.
     *
     * @param sep `Bytes` sequence to split at
     * @return a tuple of head and tail of the split instance
     */
    std::tuple<Bytes, Bytes> split1(const Bytes& sep) const {
        auto p = hilti::rt::split1(str(), sep);
        return std::make_tuple(p.first, p.second);
    }

    /**
     * Returns the concatenation of all elements in the *parts* list rendered
     * as printable strings and separated by the bytes value providing this
     * method.
     */
    template<typename T>
    Bytes join(const Vector<T>& parts) const {
        Bytes rval;

        for ( size_t i = 0; i < parts.size(); ++i ) {
            if ( i > 0 )
                rval += *this;

            rval += Bytes(hilti::rt::to_string_for_print(parts[i]).data());
        }

        return rval;
    }

    /**
     * Interprets the data as an ASCII representation of a signed integer and
     * extracts that.
     *
     * @param base base to use for conversion
     * @return converted integer value
     */
    integer::safe<int64_t> toInt(uint64_t base = 10) const;

    /**
     * Interprets the data as an ASCII representation of an unsigned integer
     * and extracts that.
     *
     * @param base base to use for conversion
     * @return converted integer value
     */
    integer::safe<uint64_t> toUInt(uint64_t base = 10) const;

    /**
     * Interprets the data as an binary representation of a signed integer
     * and extracts that.
     *
     * @param byte_order byte order that the integer is encoded in
     * @return converted integer value
     */
    int64_t toInt(hilti::rt::ByteOrder byte_order) const;

    /**
     * Interprets the data as an binary representation of an unsigned
     * integer and extracts that.
     *
     * @param byte_order byte order that the integer is encoded in
     * @return converted integer value
     */
    uint64_t toUInt(hilti::rt::ByteOrder byte_order) const;

    /**
     * Interprets the data as an ASCII representation of a integer value
     * representing seconds since the UNIX epoch, and extracts that.
     *
     * @param base base to use for conversion
     * @return converted time value
     */
    Time toTime(uint64_t base = 10) const {
        auto ns = ! isEmpty() ? toUInt(base) * integer::safe<uint64_t>(1'000'000'000) : integer::safe<uint64_t>(0);
        return Time(ns, Time::NanosecondTag());
    }

    /**
     * Interprets the data as an binary representation of a integer value
     * representing seconds since the UNIX epoch, and extracts that.
     *
     * @param base base to use for conversion
     * @return converted time value
     */
    Time toTime(hilti::rt::ByteOrder byte_order) const {
        return Time(toUInt(byte_order) * integer::safe<uint64_t>(1'000'000'000), Time::NanosecondTag());
    }

    /**
     * Matchs the data against a regular expression.
     *
     * @param re compiled regular expression
     * @param group capture group to return
     * @return the matching group, or unset if no match
     */
    Result<Bytes> match(const RegExp& re, unsigned int group = 0) const;

    // Add some operators over `Base`.
    friend bool operator==(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) == static_cast<const Bytes::Base&>(b);
    }

    friend bool operator!=(const Bytes& a, const Bytes& b) { return ! (a == b); }


    friend bool operator<(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) < static_cast<const Bytes::Base&>(b);
    }

    friend bool operator<=(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) <= static_cast<const Bytes::Base&>(b);
    }

    friend bool operator>(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) > static_cast<const Bytes::Base&>(b);
    }

    friend bool operator>=(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) >= static_cast<const Bytes::Base&>(b);
    }

    friend Bytes operator+(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) + static_cast<const Bytes::Base&>(b);
    }

private:
    friend bytes::Iterator;
    std::shared_ptr<Base*> _control;

    void invalidateIterators() { _control = std::make_shared<Base*>(static_cast<Base*>(this)); }
};

inline std::ostream& operator<<(std::ostream& out, const Bytes& x) {
    out << escapeBytes(x.str(), false);
    return out;
}

namespace bytes {
inline namespace literals {
inline Bytes operator"" _b(const char* str, size_t size) { return Bytes(Bytes::Base(str, size)); }
} // namespace literals
} // namespace bytes

template<>
inline std::string detail::to_string_for_print<Bytes>(const Bytes& x) {
    return escapeBytes(x.str(), false);
}

namespace detail::adl {
std::string to_string(const Bytes& x, adl::tag /*unused*/);
std::string to_string(const bytes::Side& x, adl::tag /*unused*/);
std::string to_string(const bytes::Charset& x, adl::tag /*unused*/);
} // namespace detail::adl

} // namespace hilti::rt
