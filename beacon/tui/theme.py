"""Beacon's dark terminal palette, shared by widgets and Rich content."""

from textual.theme import Theme

ROYAL_BLUE = "#4169E1"
BLUE_TEXT = "#8BA4FF"
MUTED = "#9AA9C1"
OK = "#77D6A0"
FAIL = "#FF8798"

BEACON_DARK = Theme(
    name="beacon-dark",
    dark=True,
    primary=ROYAL_BLUE,
    secondary=ROYAL_BLUE,
    accent=ROYAL_BLUE,
    background="#0B1020",
    surface="#111A2E",
    panel="#18233B",
    foreground="#E6EDF7",
    success=OK,
    warning="#F5C76B",
    error=FAIL,
    variables={
        "text-muted": MUTED,
        "button-color-foreground": "#FFFFFF",
        "button-focus-text-style": "bold underline",
        "input-selection-background": ROYAL_BLUE,
        "input-selection-foreground": "#FFFFFF",
        "footer-key-foreground": BLUE_TEXT,
        "footer-description-foreground": "#E6EDF7",
    },
)
