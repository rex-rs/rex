#!/usr/bin/env python3
import sys
from collections import deque

import clang.cindex as cl

needed = {'bpf_object', 'bpf_program', 'bpf_map', 'bpf_sec_def'}


def main(argv):
    rex_root = argv[1]
    output_file = argv[2]

    filename = f'{rex_root}/linux/tools/lib/bpf/libbpf.c'
    tu = cl.Index.create().parse(filename)

    wq = deque()
    found = dict()

    # First find the definitions of the needed structs
    for cursor in tu.cursor.walk_preorder():
        # Discard non-local nodes
        file = cursor.location.file
        if file and file.name != filename:
            continue

        if (
            cursor.is_definition()
            and cursor.kind
            in {
                cl.CursorKind.STRUCT_DECL,
                cl.CursorKind.ENUM_DECL,
                cl.CursorKind.TYPEDEF_DECL,
            }
            and cursor.displayname in needed
        ):
            wq.append(cursor)
            found[f'struct {cursor.displayname}'] = cursor

    # Now use a workqueue to traverse the struct definitions recursively
    while len(wq) != 0:
        curr = wq.popleft()

        # Add all field types of the current struct to the workqueue
        for cursor in curr.walk_preorder():
            if cursor.kind != cl.CursorKind.FIELD_DECL:
                continue

            ct = cursor.type.get_canonical()

            # Canonicalize struct foo * to just struct foo
            if ct.kind == cl.TypeKind.POINTER:
                ct = ct.get_pointee()

            # Discard anything that is not a C struct/enum
            if ct.kind not in {cl.TypeKind.RECORD, cl.TypeKind.ENUM}:
                continue

            decl = ct.get_declaration()
            file = decl.location.file
            # Again, discard any non-local nodes
            if not file or file.name != filename or ct.spelling in found:
                continue

            wq.append(decl)
            # Note: we do not need to store the node of anon-structs, because
            # they are already emmbedded in the current struct
            found[ct.spelling] = decl if not decl.is_anonymous() else None

    # Workqueue traverse the definitions top-down, but we need them to be
    # bottom-up in the generated header file
    vals = list(filter(lambda v: v, found.values()))[::-1]
    with open(filename) as source:
        raw = source.read()

    # Map each AST node to its raw span in the source file
    body = '\n\n'.join(
        map(lambda v: raw[v.extent.start.offset : v.extent.end.offset + 1], vals)
    )

    content = f"""#ifndef _LIBREX_BINDINGS_H
#define _LIBREX_BINDINGS_H

#include <bpf/libbpf.h>
#include <gelf.h>

#define SHA256_DIGEST_LENGTH 32

    {body}

#endif // _LIBREX_BINDINGS_H"""

    with open(output_file, 'w') as fout:
        fout.write(content)

    return 0


if __name__ == '__main__':
    exit(main(sys.argv))
