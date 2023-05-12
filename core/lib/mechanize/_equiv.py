#!/usr/bin/env python
# vim:fileencoding=utf-8
# Copyright: 2017, Kovid Goyal <kovid at kovidgoyal.net>

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import re
import string

from ._entities import html5_entities
from .polyglot import codepoint_to_chr

space_chars = frozenset(("\t", "\n", "\u000C", " ", "\r"))
space_chars_bytes = frozenset(item.encode("ascii") for item in space_chars)
ascii_letters_bytes = frozenset(
    item.encode("ascii") for item in string.ascii_letters)
spaces_angle_brackets = space_chars_bytes | frozenset((b">", b"<"))
skip1 = space_chars_bytes | frozenset((b"/", ))
head_elems = frozenset((
    b"html", b"head", b"title", b"base", b"script",
    b"style", b"meta", b"link", b"object"))


def my_unichr(num):
    try:
        return codepoint_to_chr(num)
    except (ValueError, OverflowError):
        return '?'


def replace_entity(match):
    ent = match.group(1).lower()
    if ent in {'apos', 'squot'}:
        # squot is generated by some broken CMS software
        return "'"
    if ent == 'hellips':
        ent = 'hellip'
    if ent.startswith('#'):
        try:
            num = int(ent[2:], 16) if ent[1] in ('x', 'X') else int(ent[1:])
        except Exception:
            return f'&{ent};'
        if num > 255:
            return my_unichr(num)
        try:
            return chr(num).decode('cp1252')
        except UnicodeDecodeError:
            return my_unichr(num)
    try:
        return html5_entities[ent]
    except KeyError:
        pass
    return f'&{ent};'


class Bytes(bytes):
    """String-like object with an associated position and various extra methods
    If the position is ever greater than the string length then an exception is
    raised"""

    def __init__(self, value):
        self._position = -1

    def __iter__(self):
        return self

    def __next__(self):
        p = self._position = self._position + 1
        if p >= len(self):
            raise StopIteration
        elif p < 0:
            raise TypeError
        return self[p:p + 1]

    def next(self):
        # Py2 compat
        return self.__next__()

    def previous(self):
        p = self._position
        if p >= len(self):
            raise StopIteration
        elif p < 0:
            raise TypeError
        self._position = p = p - 1
        return self[p:p + 1]

    @property
    def position(self):
        if self._position >= len(self):
            raise StopIteration
        if self._position >= 0:
            return self._position

    @position.setter
    def position(self, position):
        if self._position >= len(self):
            raise StopIteration
        self._position = position

    @property
    def current_byte(self):
        return self[self.position:self.position + 1]

    def skip(self, chars=space_chars_bytes):
        """Skip past a list of characters"""
        p = self.position  # use property for the error-checking
        while p < len(self):
            c = self[p:p + 1]
            if c not in chars:
                self._position = p
                return c
            p += 1
        self._position = p
        return

    def skip_until(self, chars):
        p = pos = self.position
        while p < len(self):
            c = self[p:p + 1]
            if c in chars:
                self._position = p
                return self[pos:p], c
            p += 1
        self._position = p
        return b'', b''

    def match_bytes(self, bytes):
        """Look for a sequence of bytes at the start of a string. If the bytes
        are found return True and advance the position to the byte after the
        match. Otherwise return False and leave the position alone"""
        p = self.position
        data = self[p:p + len(bytes)]
        rv = data.startswith(bytes)
        if rv:
            self.position += len(bytes)
        return rv

    def match_bytes_pat(self, pat):
        bytes = pat.pattern
        m = pat.match(self, self.position)
        if m is None:
            return False
        bytes = m.group()
        self.position += len(bytes)
        return True

    def jump_to(self, bytes):
        """Look for the next sequence of bytes matching a given sequence. If
        a match is found advance the position to the last byte of the match"""
        new_pos = self.find(bytes, max(0, self.position))
        if new_pos > -1:
            new_pos -= self.position
            if self._position == -1:
                self._position = 0
            self._position += (new_pos + len(bytes) - 1)
            return True
        else:
            raise StopIteration


class HTTPEquivParser(object):
    """Mini parser for detecting http-equiv headers from meta tags """

    def __init__(self, data):
        """string - the data to work on """
        self.data = Bytes(data)
        self.headers = []

    def __call__(self):
        mb, mbp = self.data.match_bytes, self.data.match_bytes_pat
        dispatch = (
                (mb, b"<!--", self.handle_comment),
                (mbp, re.compile(b"<meta", flags=re.IGNORECASE),
                    self.handle_meta),
                (mbp, re.compile(b"</head", flags=re.IGNORECASE),
                    lambda: False),
                (mb, b"</", self.handle_possible_end_tag),
                (mb, b"<!", self.handle_other),
                (mb, b"<?", self.handle_other),
                (mb, b"<", self.handle_possible_start_tag)
        )
        for _ in self.data:
            keep_parsing = True
            for matcher, key, method in dispatch:
                if matcher(key):
                    try:
                        keep_parsing = method()
                        break
                    except StopIteration:
                        keep_parsing = False
                        break
            if not keep_parsing:
                break

        ans = []
        entity_pat = re.compile(r'&(\S+?);')
        for name, val in self.headers:
            try:
                name, val = name.decode('ascii'), val.decode('ascii')
            except ValueError:
                continue
            name = entity_pat.sub(replace_entity, name)
            val = entity_pat.sub(replace_entity, val)
            try:
                name, val = name.encode('ascii'), val.encode('ascii')
            except ValueError:
                continue
            ans.append((name, val))
        return ans

    def handle_comment(self):
        """Skip over comments"""
        return self.data.jump_to(b"-->")

    def handle_meta(self):
        if self.data.current_byte not in space_chars_bytes:
            # if we have <meta not followed by a space so just keep going
            return True
        # We have a valid meta element we want to search for attributes
        pending_header = pending_content = None

        while True:
            # Try to find the next attribute after the current position
            attr = self.get_attribute()
            if attr is None:
                return True
            name, val = attr
            name = name.lower()
            if name == b"http-equiv":
                if val:
                    val = val.lower()
                    if pending_content:
                        self.headers.append((val, pending_content))
                        return True
                    pending_header = val
            elif name == b'content':
                if val:
                    if pending_header:
                        self.headers.append((pending_header, val))
                        return True
                    pending_content = val
        return True

    def handle_possible_start_tag(self):
        return self.handle_possible_tag(False)

    def handle_possible_end_tag(self):
        next(self.data)
        return self.handle_possible_tag(True)

    def handle_possible_tag(self, end_tag):
        data = self.data
        if data.current_byte not in ascii_letters_bytes:
            # If the next byte is not an ascii letter either ignore this
            # fragment (possible start tag case) or treat it according to
            # handle_other
            if end_tag:
                data.previous()
                self.handle_other()
            return True

        tag_name, c = data.skip_until(spaces_angle_brackets)
        tag_name = tag_name.lower()
        if not end_tag and tag_name not in head_elems:
            return False
        if c == b"<":
            # return to the first step in the overall "two step" algorithm
            # reprocessing the < byte
            data.previous()
        else:
            # Read all attributes
            attr = self.get_attribute()
            while attr is not None:
                attr = self.get_attribute()
        return True

    def handle_other(self):
        return self.data.jump_to(b">")

    def get_attribute(self):
        """Return a name,value pair for the next attribute in the stream,
        if one is found, or None"""
        data = self.data
        # Step 1 (skip chars)
        c = data.skip(skip1)
        assert c is None or len(c) == 1
        # Step 2
        if c in (b">", None):
            return None
        # Step 3
        attr_name = []
        attr_value = []
        # Step 4 attribute name
        while True:
            if c == b"=" and attr_name:
                break
            elif c in space_chars_bytes:
                # Step 6!
                c = data.skip()
                break
            elif c in (b"/", b">"):
                return b"".join(attr_name), b""
            elif c is None:
                return None
            else:
                attr_name.append(c)
            # Step 5
            c = next(data)
        # Step 7
        if c != b"=":
            data.previous()
            return b"".join(attr_name), b""
        # Step 8
        next(data)
        # Step 9
        c = data.skip()
        # Step 10
        if c in (b"'", b'"'):
            # 10.1
            quote_char = c
            while True:
                # 10.2
                c = next(data)
                # 10.3
                if c == quote_char:
                    next(data)
                    return b"".join(attr_name), b"".join(attr_value)
                # 10.4
                else:
                    attr_value.append(c)
        elif c == b">":
            return b"".join(attr_name), b""
        elif c is None:
            return None
        else:
            attr_value.append(c)
        # Step 11
        while True:
            c = next(data)
            if c in spaces_angle_brackets:
                return b"".join(attr_name), b"".join(attr_value)
            elif c is None:
                return None
            else:
                attr_value.append(c)
