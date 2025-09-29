
FROM node:18-bullseye

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*


RUN pip3 install --no-cache-dir slither-analyzer solc-select


RUN solc-select install 0.8.19 && solc-select use 0.8.19
RUN solc-select install 0.8.9
RUN solc-select install 0.8.21

WORKDIR /app

COPY package*.json ./

RUN npm install --production
COPY . .

RUN mkdir -p temp blockchain/contracts/fetched blockchain/scripts blockchain/artifacts

RUN chmod -R 755 /app
ENV DOCKER_ENV=true
ENV NODE_ENV=production
ENV PORT=3000


EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/ping', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
CMD ["node", "server.js"]