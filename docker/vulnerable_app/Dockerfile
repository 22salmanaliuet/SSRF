FROM python:3.11-slim

LABEL maintainer="SEDF FYP - Educational Use Only"
LABEL description="Intentionally vulnerable SSRF lab application"

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask==3.0.0

COPY app.py .

# Expose app port
EXPOSE 5000

# Create lab system users (intentionally vulnerable for SSRF demo)
# These users simulate a real server with multiple accounts
RUN useradd -m labuser && \
    useradd -m -s /bin/bash -u 1001 salman && \
    useradd -m -s /bin/bash -u 1002 faisal && \
    useradd -m -s /bin/bash -u 1003 admin && \
    # Set passwords via /etc/shadow (SHA-512 hashed)
    echo 'salman:$6$WrKiM97TDIMxwfEw$GmD5rMVxcfEPP8TzNL437k8uUc1uYXBX3cQ67/phaff4V7IhcAd8gafum/Uma.x8Ovu4aHFH1VS5bKyObMxGs0:19919:0:99999:7:::' >> /etc/shadow && \
    echo 'faisal:$6$miJFzUqXWudSx6.F$voOS6JzezSfZbsbRtDKqLlm2vKOAB.1D9P0R4CMn5nMYDp2hBb1Xb/dxhhy0NHiUwEy/HdCZjCnmt3UM7gWgv/:19919:0:99999:7:::' >> /etc/shadow && \
    echo 'admin:$6$uGWNGzE3Fe6R.TAK$JLlFDsJXGSRiG.uD8Sqg3A1itbLAI9dzknwclB7/1Butj394/R5UNtZeB0icIEmCj/k01F2hEtj.xZPHJ2H281:19919:0:99999:7:::' >> /etc/shadow

USER labuser

ENV PORT=5000
ENV FLASK_ENV=development

CMD ["python", "app.py"]
