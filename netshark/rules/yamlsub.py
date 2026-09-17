"""Hand-rolled strict-subset YAML parser supporting nested dicts, lists, scalars, and line-numbered errors."""

from typing import Any, Dict, List, Tuple, Union


class YAMLParseError(Exception):
    """Custom exception raised when YAML parsing fails, providing exact line number and context."""

    def __init__(self, message: str, line_num: int, line_content: str):
        self.line_num = line_num
        self.line_content = line_content
        super().__init__(f"YAMLParseError at line {line_num}: {message}\n  -> {line_content.strip()}")


def _parse_scalar(value_str: str) -> Union[int, float, bool, str, None]:
    """Parses scalar YAML values into Python primitive types."""
    val = value_str.strip()
    if not val:
        return None

    # Strip quotes if present
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]

    # Booleans
    val_lower = val.lower()
    if val_lower in ("true", "yes", "on"):
        return True
    if val_lower in ("false", "no", "off"):
        return False
    if val_lower in ("null", "none", "~"):
        return None

    # Integers
    try:
        return int(val)
    except ValueError:
        pass

    # Floats
    try:
        return float(val)
    except ValueError:
        pass

    return val


def parse_yaml_subset(yaml_content: str) -> Dict[str, Any]:
    """Parses a strict subset of YAML into Python dictionaries/lists with line number tracking."""
    lines = yaml_content.splitlines()

    # Pre-process lines: store (line_number, indentation, stripped_content, raw_line)
    processed_lines = []
    for idx, raw in enumerate(lines, start=1):
        # Remove comments starting with '#' unless inside quotes
        comment_pos = -1
        in_quote = False
        quote_char = None
        for i, char in enumerate(raw):
            if char in ('"', "'"):
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif quote_char == char:
                    in_quote = False
            elif char == '#' and not in_quote:
                comment_pos = i
                break

        line_no_comment = raw[:comment_pos] if comment_pos != -1 else raw
        stripped = line_no_comment.strip()

        if not stripped:
            continue

        indentation = len(line_no_comment) - len(line_no_comment.lstrip(" "))
        processed_lines.append((idx, indentation, stripped, raw))

    if not processed_lines:
        return {}

    def _parse_block(index: int, min_indent: int) -> Tuple[Any, int]:
        """Recursive helper parsing blocks based on indentation levels."""
        if index >= len(processed_lines):
            return {}, index

        line_num, indent, content, raw = processed_lines[index]

        # Check if block is a list
        if content.startswith("- "):
            result_list = []
            curr_idx = index
            while curr_idx < len(processed_lines):
                l_num, l_indent, l_content, l_raw = processed_lines[curr_idx]
                if l_indent < min_indent:
                    break
                if not l_content.startswith("- "):
                    break

                item_text = l_content[2:].strip()
                curr_idx += 1

                # Check if item text has key: value or is a scalar
                if ":" in item_text and not (item_text.startswith('"') or item_text.startswith("'")):
                    k, v = item_text.split(":", 1)
                    dict_item = {k.strip(): _parse_scalar(v)}
                    # Check for nested sub-items under this list item
                    if curr_idx < len(processed_lines) and processed_lines[curr_idx][0] > l_indent:
                        nested_val, curr_idx = _parse_block(curr_idx, processed_lines[curr_idx][1])
                        if isinstance(nested_val, dict):
                            dict_item.update(nested_val)
                    result_list.append(dict_item)
                else:
                    result_list.append(_parse_scalar(item_text))

            return result_list, curr_idx

        # Block is a dictionary
        result_dict = {}
        curr_idx = index

        while curr_idx < len(processed_lines):
            l_num, l_indent, l_content, l_raw = processed_lines[curr_idx]

            if l_indent < min_indent:
                break

            if ":" not in l_content:
                raise YAMLParseError("Expected key-value pair separated by ':'", l_num, l_raw)

            key_part, val_part = l_content.split(":", 1)
            key = key_part.strip()
            val_text = val_part.strip()

            curr_idx += 1

            if val_text:
                result_dict[key] = _parse_scalar(val_text)
            else:
                # Value is on subsequent indented lines (dictionary or list)
                if curr_idx < len(processed_lines) and processed_lines[curr_idx][1] > l_indent:
                    sub_val, curr_idx = _parse_block(curr_idx, processed_lines[curr_idx][1])
                    result_dict[key] = sub_val
                else:
                    result_dict[key] = None

        return result_dict, curr_idx

    parsed, _ = _parse_block(0, 0)
    return parsed if isinstance(parsed, dict) else {"items": parsed}


def load_yaml_file(filepath: str) -> Dict[str, Any]:
    """Reads and parses a YAML file."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return parse_yaml_subset(content)
