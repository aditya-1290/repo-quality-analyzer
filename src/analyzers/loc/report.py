from .models import LOCAggregate

def build_report(agg: LOCAggregate, stats: dict) -> dict:
    report = {
        "summary": agg.as_dict(),
        "statistics": stats,
        "files": [],
    }

    for f in agg.files:
        report["files"].append({
            "path": f.path,
            "total": f.total_lines,
            "code": f.code_lines,
            "blank": f.blank_lines,
            "comment": f.comment_lines,
        })

    return report
