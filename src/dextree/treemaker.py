from dataclasses import dataclass
from typing import TypeAlias
from typing_extensions import Dict, List, Optional, Set, Self, Iterable, Callable
from lief import DEX
from dextree.treeformat import fmt_type, fmt_string
from dextree.dex_ints import parse_instructions, INSTRUCTIONS

JustName: TypeAlias = str


@dataclass
class TreeString(object):
    value: str

    def __str__(self):
        return f'{self.value}'


@dataclass
class TreeField(object):
    name: str
    type: str
    is_static: bool
    string_value: Optional[TreeString]

    @staticmethod
    def new(name: str, type: str, is_static: bool) -> Self:
        return TreeField(name, type, is_static, None)


@dataclass
class TreeMethod(object):
    name: str
    parameter_types: List[str]
    return_type: str
    access_flags: Iterable[DEX.ACCESS_FLAGS]
    string_values: List[TreeString]

    @property
    def is_static(self):
        return DEX.ACCESS_FLAGS.STATIC in self.access_flags

    def __str__(self):
        return f'TreeMethod({self.return_type} {self.name}(#parameters={len(self.parameter_types)}))'

    @staticmethod
    def new(
        name: str,
        parameter_types: List[str],
        return_type: str,
        access_flags: Iterable[DEX.ACCESS_FLAGS],
    ) -> Self:
        return TreeMethod(name, parameter_types, return_type, access_flags, [])


@dataclass
class TreeClass(object):
    path: str
    name: JustName
    fields: List[TreeField]
    methods: List[TreeMethod]

    def __str__(self):
        return f'TreeClass({self.path}/{self.name}, #fields={len(self.fields)}, #methods={len(self.methods)})'  # noqa

    @staticmethod
    def new(path: str, name: JustName) -> Self:
        return TreeClass(path, name, [], [])


@dataclass
class TreePackage(object):
    path: str
    name: JustName
    packages: Dict[JustName, Self]
    classes: Dict[JustName, TreeClass]

    def __str__(self):
        return f'TreePackage({self.path}/{self.name}, #packages={len(self.packages)}, #classes={len(self.classes)})'

    @staticmethod
    def new(path: str, name: JustName) -> Self:
        return TreePackage(path, name, {}, {})

    def iterate(self, callback):
        def iterate_it(item, cb, depth=[]):
            cb(item, depth)
            if isinstance(item, TreePackage):
                for_each(
                    item.packages.values(),
                    lambda item, is_last: iterate_it(
                        item, cb, depth + [not is_last or len(item.classes) > 0]
                    ),
                )
                for_each(
                    item.classes.values(),
                    lambda item, is_last: iterate_it(item, cb, depth + [not is_last]),
                )
            elif isinstance(item, TreeClass):
                for_each(
                    item.fields,
                    lambda item, is_last: iterate_it(
                        item, cb, depth + [not is_last or len(item.methods) > 0]
                    ),
                )
                for_each(
                    item.methods,
                    lambda item, is_last: iterate_it(item, cb, depth + [not is_last]),
                )
            elif isinstance(item, TreeMethod):
                for_each(
                    item.string_values,
                    lambda item, is_last: iterate_it(item, cb, depth + [not is_last]),
                )
            elif isinstance(item, TreeField):
                if item.string_value:
                    iterate_it(item.string_value, cb, depth + [False])

        iterate_it(self, lambda item, depth: callback(item, depth))


class RootPackage(TreePackage):
    def __init__(self):
        super().__init__('', '', {}, {})

    def get(self, package_name: str) -> TreePackage:
        if len(package_name) == 0:
            return self
        parts = package_name.split('/')
        parent = self
        for i in range(len(parts)):
            parent = parent.packages[parts[i]]
            if not parent:
                break
        return parent


def for_each[T](items: Iterable[T], fn: Callable[[T, bool], None]):
    length = len(items)
    for i, item in enumerate(items):
        fn(item, i == length - 1)


def gen_packages_sorted(dex: DEX.File) -> List[str]:
    gen: Set[tuple] = set()
    for clazz in dex.classes:
        parts = clazz.package_name.split('/')
        while len(parts) > 0:
            gen.add(tuple(parts))
            parts.pop()
    return sorted(gen, key=len)


def treeify(dex: DEX.File, code=False, fields=False) -> RootPackage:
    root = RootPackage()

    # make packages
    gens = gen_packages_sorted(dex)
    for gen in gens:
        path = '/'.join(gen[:-1])
        name = gen[-1]
        parent = root.get(path)
        parent.packages[name] = TreePackage.new(path, name)

    # iterate all classes
    for clazz in dex.classes:
        parent = root.get(clazz.package_name)
        path = clazz.package_name
        name = clazz.name
        parent.classes[name] = TreeClass.new(path, name)
        parent = parent.classes[name]

        # iterate all fields in class
        if fields:
            for field in clazz.fields:
                item = TreeField.new(field.name, field.type, field.is_static)
                parent.fields.append(item)

        # iterate all methods in class
        for method in clazz.methods:
            proto = method.prototype
            parameter_types = proto.parameters_type
            return_type = proto.return_type
            flags = method.access_flags
            item = TreeMethod.new(method.name, parameter_types, return_type, flags)
            parent.methods.append(item)

            if code:
                parsed = parse_instructions(method, dex)
                for insn, parse in parsed:
                    # text = f"{insn.label} {', '.join(parse)}"
                    if insn.label.startswith('const-string'):
                        text = parse[-1]
                        item.string_values.append(TreeString(text))

    return root
