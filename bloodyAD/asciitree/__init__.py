#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .drawing import BoxStyle
from .traversal import DictTraversal
from .util import KeyArgsConstructor
from bloodyAD.formatters import common, formatters


# Explore the trust_dict level by level and populate a branch provided in to_explore
def branchFactory(to_explore, explored, trust_dict):
    next_explore = {}
    for ascii_parent, parent_dict in to_explore.items():
        parent = ascii_parent.rsplit(":")[-1]
        if parent in explored:
            continue
        explored.append(parent)

        for child_name, child in trust_dict.get(parent, {}).items():
            # If it's a root key in trust_dict, it means we have been able to connect to it and explore it
            # So there is somewhere an INBOUND parent
            # So do not print the node below this parent, it will be printed below one with INBOUND
            if not (
                int(child["trustDirection"][0].decode())
                & common.TRUST_DIRECTION["INBOUND"]
            ) and (child_name in trust_dict):
                continue
            # If it's already explored no need to print it again it will only show the opposite trust direction and nothing new
            if child_name in explored:
                continue

            # Format child in ascii representation
            ascii_child = ""
            flags = []
            if (
                int(child["trustDirection"][0].decode())
                & common.TRUST_DIRECTION["OUTBOUND"]
            ):
                ascii_child += "<"
            # TODO: trustAttributes not printed all the time, find the root cause and fix it
            trustFlags = formatters.formatTrustAttributes(child["trustAttributes"][0])
            if trustFlags:
                flags += trustFlags
            else:
                flags += [child["trustAttributes"][0].decode()]
            flags.append(formatters.formatTrustType(child["trustType"][0]))
            ascii_child += "|".join(flags)
            if (
                int(child["trustDirection"][0].decode())
                & common.TRUST_DIRECTION["INBOUND"]
            ):
                ascii_child += ">"
            ascii_child += ":" + child["trustPartner"][0].decode()
            parent_dict[ascii_child] = {}

        next_explore = {**next_explore, **parent_dict}

    if next_explore:
        branchFactory(next_explore, explored, trust_dict)


class LeftAligned(KeyArgsConstructor):
    """Creates a renderer for a left-aligned tree.

    Any attributes of the resulting class instances can be set using
    constructor arguments."""

    draw = BoxStyle()
    "The draw style used. See :class:`~asciitree.drawing.Style`."
    traverse = DictTraversal()
    "Traversal method. See :class:`~asciitree.traversal.Traversal`."

    def render(self, node):
        """Renders a node. This function is used internally, as it returns
        a list of lines. Use :func:`~asciitree.LeftAligned.__call__` instead.
        """
        lines = []

        children = self.traverse.get_children(node)
        lines.append(self.draw.node_label(self.traverse.get_text(node)))

        for n, child in enumerate(children):
            child_tree = self.render(child)

            if n == len(children) - 1:
                # last child does not get the line drawn
                lines.append(self.draw.last_child_head(child_tree.pop(0)))
                lines.extend(self.draw.last_child_tail(l) for l in child_tree)
            else:
                lines.append(self.draw.child_head(child_tree.pop(0)))
                lines.extend(self.draw.child_tail(l) for l in child_tree)

        return lines

    def __call__(self, tree):
        """Render the tree into string suitable for console output.

        :param tree: A tree."""
        return "\n".join(self.render(self.traverse.get_root(tree)))


# legacy support below

from .drawing import Style
from .traversal import Traversal


class LegacyStyle(Style):
    def node_label(self, text):
        return text

    def child_head(self, label):
        return "  +--" + label

    def child_tail(self, line):
        return "  |" + line

    def last_child_head(self, label):
        return "  +--" + label

    def last_child_tail(self, line):
        return "   " + line


def draw_tree(node, child_iter=lambda n: n.children, text_str=str):
    """Support asciitree 0.2 API.

    This function solely exist to not break old code (using asciitree 0.2).
    Its use is deprecated."""
    return LeftAligned(
        traverse=Traversal(get_text=text_str, get_children=child_iter),
        draw=LegacyStyle(),
    )(node)
