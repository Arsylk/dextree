from lief import DEX
from colors import color


CLASS_FMT = lambda t: color(t, fg='yellow')
PRIMITIVE_FMT = lambda t: color(t, fg='yellow')
ARRAY_BRACKETS_FMT = lambda t: color(t, fg='red')
FUNCTION_FMT = lambda t: color(t, fg='blue')
FIELD_FMT = lambda t: color(t, fg='#b4befe')
STRING_FMT = lambda t: color(t, fg='green')
BRACKET_FMT = lambda t: color(t, fg='#94e2d5')
KEYWORD_FMT = lambda t: color(t, fg='#cba6f7')


def fmt_type(type: DEX.Type | str) -> str:
    type_text = f'{type}'.replace('[]', '')
    dim = (
        type.dim
        if isinstance(type, DEX.Type)
        else (len(f'{type}') - len(type_text)) // 2
    )

    type_text = type_text.replace('/', '.').strip()
    if len(type_text) == 0:
        return ''

    if type_text[0] == 'L' and type_text[-1] == ';':
        type_text = type_text[1:-1]
        type_text = '.'.join(map(CLASS_FMT, type_text.split('.')))
    else:
        type_text = 'boolean' if type_text == 'bool' else type_text
        type_text = PRIMITIVE_FMT(type_text)
    array_text = '[]' * dim

    return f'{type_text}{ARRAY_BRACKETS_FMT(array_text)}'


def fmt_function(name: str) -> str:
    if len(name) == 0:
        return 0
    return FUNCTION_FMT(name)


def fmt_field(name: str) -> str:
    return FIELD_FMT(name)


def fmt_string(string: str) -> str:
    return f'{STRING_FMT(string)}'


def fmt_bracket(bracket: str) -> str:
    return f'{BRACKET_FMT(bracket)}'


def fmt_keyword(word: str) -> str:
    return f'{KEYWORD_FMT(word)}'.lower()
