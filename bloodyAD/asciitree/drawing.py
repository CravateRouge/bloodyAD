from .util import KeyArgsConstructor

BOX_LIGHT = {
    "UP_AND_RIGHT": "\u2514",
    "HORIZONTAL": "\u2500",
    "VERTICAL": "\u2502",
    "VERTICAL_AND_RIGHT": "\u251c",
}  #: Unicode box-drawing glyphs, light style


BOX_HEAVY = {
    "UP_AND_RIGHT": "\u2517",
    "HORIZONTAL": "\u2501",
    "VERTICAL": "\u2503",
    "VERTICAL_AND_RIGHT": "\u2523",
}  #: Unicode box-drawing glyphs, heavy style


BOX_DOUBLE = {
    "UP_AND_RIGHT": "\u255a",
    "HORIZONTAL": "\u2550",
    "VERTICAL": "\u2551",
    "VERTICAL_AND_RIGHT": "\u2560",
}  #: Unicode box-drawing glyphs, double-line style


BOX_ASCII = {
    "UP_AND_RIGHT": "+",
    "HORIZONTAL": "-",
    "VERTICAL": "|",
    "VERTICAL_AND_RIGHT": "+",
}  #: Unicode box-drawing glyphs, using only ascii ``|+-`` characters.


BOX_BLANK = {
    "UP_AND_RIGHT": " ",
    "HORIZONTAL": " ",
    "VERTICAL": " ",
    "VERTICAL_AND_RIGHT": " ",
}  #: Unicode box-drawing glyphs, using only spaces.


class Style(KeyArgsConstructor):
    """Rendering style for trees."""

    label_format = "{}"  #: Format for labels.

    def node_label(self, text):
        """Render a node text into a label."""
        return self.label_format.format(text)

    def child_head(self, label):
        """Render a node label into final output."""
        return label

    def child_tail(self, line):
        """Render a node line that is not a label into final output."""
        return line

    def last_child_head(self, label):
        """Like :func:`~asciitree.drawing.Style.child_head` but only called
        for the last child."""
        return label

    def last_child_tail(self, line):
        """Like :func:`~asciitree.drawing.Style.child_tail` but only called
        for the last child."""
        return line


class BoxStyle(Style):
    """A rendering style that uses box draw characters and a common layout."""

    gfx = BOX_ASCII  #: Glyhps to use.
    label_space = 1  #: Space between glyphs and label.
    horiz_len = 2  #: Length of horizontal lines
    indent = 1  #: Indent for subtrees

    def child_head(self, label):
        return (
            " " * self.indent
            + self.gfx["VERTICAL_AND_RIGHT"]
            + self.gfx["HORIZONTAL"] * self.horiz_len
            + " " * self.label_space
            + label
        )

    def child_tail(self, line):
        return " " * self.indent + self.gfx["VERTICAL"] + " " * self.horiz_len + line

    def last_child_head(self, label):
        return (
            " " * self.indent
            + self.gfx["UP_AND_RIGHT"]
            + self.gfx["HORIZONTAL"] * self.horiz_len
            + " " * self.label_space
            + label
        )

    def last_child_tail(self, line):
        return (
            " " * self.indent
            + " " * len(self.gfx["VERTICAL"])
            + " " * self.horiz_len
            + line
        )
