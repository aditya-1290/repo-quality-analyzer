TEST_MARKERS = ("test_", "_test", "/tests/", "__tests__", ".spec.", ".test.")

SOURCE_EXTENSIONS = (
    ".py", ".js", ".ts", ".java", ".go", ".rs"
)

def is_test_file(path: str) -> bool:
    return any(marker in path.lower() for marker in TEST_MARKERS)

def is_source_file(path: str) -> bool:
    return path.endswith(SOURCE_EXTENSIONS)
