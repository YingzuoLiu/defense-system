smart_customer_service/
│
├── app.py                  # FastAPI 服务主文件
├── service_core.py         # 模型逻辑（含主模型 + fallback + 决策引擎）
├── logs/                   # 审计日志目录
│   └── interactions.jsonl
└── requirements.txt
