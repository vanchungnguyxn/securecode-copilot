"""Central plan catalog — seed source of truth."""

from __future__ import annotations

import json
from typing import Any, Dict, List

PLAN_CATALOG: List[Dict[str, Any]] = [
    {
        "code": "free",
        "name": "Free",
        "description": "Dùng thử cho cá nhân và học tập.",
        "price_monthly_vnd": 0,
        "price_yearly_vnd": 0,
        "monthly_limit": 5,
        "max_lines": 2000,
        "max_members": 1,
        "history_days": 7,
        "sort_order": 1,
        "features": [
            "5 lượt phân tích mỗi tháng",
            "Tối đa 2.000 dòng code mỗi lần",
            "Phân tích từng file",
            "Giải thích lỗ hổng",
            "Đề xuất bản vá cơ bản",
            "Lưu lịch sử 7 ngày",
            "Hỗ trợ cộng đồng",
        ],
    },
    {
        "code": "pro",
        "name": "Pro",
        "description": "Dành cho lập trình viên và dự án chuyên nghiệp.",
        "price_monthly_vnd": 149_000,
        "price_yearly_vnd": 1_480_000,  # ~17% off
        "monthly_limit": 100,
        "max_lines": 10_000,
        "max_members": 1,
        "history_days": -1,
        "sort_order": 2,
        "popular": True,
        "features": [
            "100 lượt phân tích mỗi tháng",
            "Tối đa 10.000 dòng code mỗi lần",
            "Phân tích nâng cao + CWE",
            "Confidence score & diff",
            "Tải báo cáo JSON",
            "Lịch sử không giới hạn trong thời gian thuê bao",
            "Ưu tiên xử lý",
        ],
    },
    {
        "code": "team",
        "name": "Team",
        "description": "Nhóm phát triển nhỏ — workspace dùng chung.",
        "price_monthly_vnd": 499_000,
        "price_yearly_vnd": 4_980_000,
        "monthly_limit": 500,
        "max_lines": 20_000,
        "max_members": 5,
        "history_days": -1,
        "sort_order": 3,
        "features": [
            "500 lượt phân tích mỗi tháng",
            "Tối đa 5 thành viên",
            "Workspace chung (sắp ra mắt đầy đủ)",
            "Dashboard theo nhóm",
            "GitHub / CI integration (sắp ra mắt)",
            "API access giới hạn",
            "Hỗ trợ ưu tiên",
        ],
    },
    {
        "code": "enterprise",
        "name": "Enterprise",
        "description": "Doanh nghiệp — quota và triển khai tùy chỉnh.",
        "price_monthly_vnd": 0,
        "price_yearly_vnd": 0,
        "monthly_limit": 10_000,
        "max_lines": 100_000,
        "max_members": 100,
        "history_days": -1,
        "sort_order": 4,
        "contact_only": True,
        "features": [
            "Quota tùy chỉnh",
            "Thành viên tùy chỉnh",
            "Private cloud / on-premise",
            "SSO & audit log",
            "SLA & hỗ trợ riêng",
            "Không lưu source code (tùy chọn)",
        ],
    },
]


def features_json(plan: Dict[str, Any]) -> str:
    return json.dumps(plan.get("features") or [], ensure_ascii=False)
