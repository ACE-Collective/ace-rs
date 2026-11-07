"""oletools' olevba, as 4.4's Python module called it."""

from oletools.olevba import VBA_Parser, filter_vba

import side


def has_content(output):
    return bool(output["macros"])


def run(path):
    output = {"type": None, "detected": None, "analysis": None, "macros": None}
    parser = None
    try:
        parser = VBA_Parser(path, relaxed=True)
        output["type"] = parser.type
        output["detected"] = parser.detect_vba_macros()
        if output["detected"]:
            output["analysis"] = list(parser.analyze_macros(show_decoded_strings=True, deobfuscate=False))
            output["macros"] = []
            for file_name, stream_path, vba_filename, code in parser.extract_all_macros():
                text = code.decode("utf8", errors="ignore") if isinstance(code, bytes) else code
                output["macros"].append(
                    {
                        "file_name": file_name,
                        "stream_path": stream_path,
                        "vba_filename": vba_filename,
                        "code": code,
                        "filtered": filter_vba(text),
                    }
                )
    except Exception as error:
        # what it gave before it raised stays in the output
        output["raised"] = side.error_data(error)
    finally:
        if parser:
            parser.close()
    return output
