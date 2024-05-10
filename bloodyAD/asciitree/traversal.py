from .util import KeyArgsConstructor


class Traversal(KeyArgsConstructor):
    """Traversal method.

    Used by the tree rendering functions like :class:`~asciitree.LeftAligned`.
    """

    def get_children(self, node):
        """Return a list of children of a node."""
        raise NotImplementedError

    def get_root(self, tree):
        """Return a node representing the tree root from the tree."""
        return tree

    def get_text(self, node):
        """Return the text associated with a node."""
        return str(node)


class DictTraversal(Traversal):
    """Traversal suitable for a dictionary. Keys are tree labels, all values
    must be dictionaries as well."""

    def get_children(self, node):
        return list(node[1].items())

    def get_root(self, tree):
        return list(tree.items())[0]

    def get_text(self, node):
        return node[0]


class AttributeTraversal(Traversal):
    """Attribute traversal.

    Uses an attribute of a node as its list of children.
    """

    attribute = "children"  #: Attribute to use.

    def get_children(self, node):
        return getattr(node, self.attribute)
