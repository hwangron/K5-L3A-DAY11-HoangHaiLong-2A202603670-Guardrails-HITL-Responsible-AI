# Lab 11 — môi trường chạy cố định Python 3.12.
# nemoguardrails (Red Advance) chưa hỗ trợ Python 3.14, README khuyến nghị 3.11/3.12.
#
#   docker build -t lab11 .
#   docker run --rm lab11                                   # pytest tests/smoke
#   docker run --rm lab11 pytest tests/public -q
#   docker run --rm -it --env-file .env -v "${PWD}/outputs:/app/outputs" lab11 python src/main.py --part 2
#   # Khi đang làm bài: mount cả repo (code + outputs + .env đọc bằng python-dotenv)
#   docker run --rm -v "${PWD}:/app" lab11 python src/main.py --part 3
#
# KHÔNG copy .env vào image (xem .dockerignore): key được truyền lúc chạy bằng --env-file
# hoặc đọc từ repo được mount.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Cài dependencies trước để Docker cache layer này khi chỉ đổi code.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["pytest", "tests/smoke", "-q"]
