# Qoder Multi-Account Reverse Proxy Gateway (CN + Intl)
FROM python:3.11-alpine

# Set environment
ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8790 \
    API_KEY= \
    TZ=Asia/Shanghai

WORKDIR /app

# Alpine timezone & certs
RUN apk add --no-cache tzdata ca-certificates && \
    cp /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo "${TZ}" > /etc/timezone

# Copy application files (Zero external pip dependencies needed -
# AES/RSA/COSY signing are pure-stdlib implementations)
COPY qoder_proxy.py qoder_accounts.py qoder_catalog.py qoder_fingerprint.py \
     qoder_scheduler.py qoder_settings.py qoder_sign.py qoder_tasks.py \
     dashboard.html baseprompt.json ./

# 官方模型目录快照（运行时优先读取；缺失会回退 qoder_catalog.py 内嵌冻结副本）
COPY qoder_catalog_intl.json qoder_catalog_cn.json ./

# 验证 / 诊断脚本一并入镜像（容器内自检用；纯标准库，零 pip 依赖）：
#   docker run --rm qoder-proxy:latest python _test_qoder.py
#   docker run --rm qoder-proxy:latest python _diag_gateway.py --chat
# 注：官方 fixture 不在镜像内，_test_qoder.py 的 [4.5] 组会打印 [SKIP]（不计失败）。
COPY _test_qoder.py _diag_gateway.py _diag_campaign.py _verify_models.py \
     _refresh_catalog.py ./

# Create data directories
RUN mkdir -p /app/accounts /app/usage

# Volume persistence for credentials and usage logs
VOLUME ["/app/accounts", "/app/usage"]

EXPOSE 8790

# 监听参数由上面的 ENV HOST/PORT 提供（qoder_proxy.py 的 argparse 默认值直接
# 读环境变量），所以 docker run -e PORT=9000 与 compose 的 environment 真的生效；
# 需要附带其它命令行参数时用 compose 的 command: 覆盖本 CMD。
CMD ["python", "qoder_proxy.py"]
