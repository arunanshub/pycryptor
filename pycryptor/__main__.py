#!/usr/bin/python3
import argparse
import logging
import tkinter as tk

from . import start_logging
from .app import APP_DESC, ControlFrame

logger = logging.getLogger(__loader__.name)

CLI_APP_EPILOG = """\
Pycryptor is licensed under MIT license.
"""


def start_logging_with_flags():
    """Add logging capability with tunable verbosity."""
    logging_levels = {
        3: logging.WARNING,
        4: logging.INFO,
        5: logging.DEBUG,
    }

    ps = argparse.ArgumentParser(
        # only the package name is needed for `prog`
        # prog=__loader__.name.split(".", 1)[0],
        prog=__name__,
        description=APP_DESC,
        epilog=CLI_APP_EPILOG,
    )
    group = ps.add_mutually_exclusive_group()
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=3,
        help="Increase application verbosity."
        " This option is repeatable and will increase verbosity each time "
        "it is repeated."
        " This option cannot be used when -q/--quiet is used.",
    )

    group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Disable logging."
        " This option cannot be used when -v/--verbose is used.",
    )

    args = ps.parse_args()

    if args.quiet:
        return

    level = args.verbose
    if level >= 5:
        level = 5

    start_logging(logging_levels[level])


def main():
    start_logging_with_flags()  # enable logging
    logger.info("Building application with grid manager.")

    root = tk.Tk()
    root.title("Pycryptor")
    cf = ControlFrame(master=root)
    cf.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    root.mainloop()
    logger.info("The application has been destroyed.")


if __name__ == "__main__":
    main()
