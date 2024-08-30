import lief
import typer
from colors import color
from lief import DEX
from typing_extensions import Annotated, List
from dextree.treeformat import (
    fmt_type,
    fmt_function,
    fmt_string,
    fmt_field,
    fmt_bracket,
    fmt_keyword,
)
from dextree.treemaker import (
    TreeClass,
    TreeField,
    TreeMethod,
    TreePackage,
    TreeString,
    treeify,
)


def logme(item, depth):
    pad = ''
    if len(depth) > 0:
        for open in depth[:-1]:
            pad += '│' if open else ' '
        pad += '├' if depth[-1] else '└'
    pad = color(pad, fg='#585b70')

    text = f'{item}'
    if isinstance(item, TreePackage):
        text = color(item.name, fg='#f5e0dc')
    elif isinstance(item, TreeClass):
        text = f'{color(item.name, fg="#f2cdcd")}.{color("class", style="faint")}'
    elif isinstance(item, TreeField):
        name = fmt_field(item.name)
        type = fmt_type(item.type)
        text = f'{type} {name}'
    elif isinstance(item, TreeMethod):
        params = ', '.join(map(fmt_type, item.parameter_types))
        ret = fmt_type(item.return_type)
        name = fmt_function(item.name)
        flags = ' '.join(map(lambda p: fmt_keyword(p.__name__), item.access_flags))
        flags = flags + ' ' if len(flags) > 0 else ''
        text = f'{flags}{ret} {name}{fmt_bracket("(")}{params}{fmt_bracket(")")}'
    elif isinstance(item, TreeString):
        text = fmt_string(item.value)

    print(f'{pad}{text}')


def main(files: Annotated[List[str], typer.Argument()]):
    # validate args
    for file in files:
        if not lief.is_dex(file):
            raise typer.Abort(f'not a dex file: {file}')

    # iterate argument files
    for file in files:
        dex = DEX.parse(file)
        assert dex is not None

        # build tree from dex
        root = treeify(dex, code=True, fields=False)

        # iterate all over tree
        root.iterate(logme)


def setuptools_main():
    import sys

    main(sys.argv[1:])


if __name__ == '__main__':
    typer.run(main)
